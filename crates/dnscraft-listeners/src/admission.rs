//! Source classification and admission (SPEC-listeners § Source classification).
//!
//! Hot-path state is sharded: per-source token buckets live in independent
//! mutexes keyed by [`source_key`] hash so UDP/DoH/DoQ bursts do not serialize
//! on one global lock. The ban table and Client-ID buckets stay process-global
//! (ADR-0004) under their own mutexes.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use dnscraft_policy::ClientId;

use crate::bans::{BanTable, StrikeReason};
use crate::config::{Exposure, Limits, ListenerConfig, Protocol, PublicConfig, TokenRate};
use crate::ratelimit::{LruMap, TokenBucket};

/// Number of per-source rate-limit shards (power of two for mask indexing).
const SOURCE_SHARDS: usize = 16;
const SOURCE_SHARD_MASK: usize = SOURCE_SHARDS - 1;

/// Private vs public client source (after `to_canonical`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

pub enum SourceClass {
    /// RFC 1918, loopback, link-local, ULA, CGNAT (and IPv4-mapped forms).
    Private,
    /// Everything else.
    Public,
}

impl SourceClass {
    /// Classifies `ip`. IPv4-mapped addresses are classified by their IPv4 part.
    pub fn of(ip: IpAddr) -> Self {
        let ip = ip.to_canonical();
        if is_private_source(ip) {
            Self::Private
        } else {
            Self::Public
        }
    }
}

/// Injectable source classifier (`Admission` and SNI/path gates).
///
/// Tests may treat selected loopback addresses (e.g. `127.0.0.2`) as
/// [`SourceClass::Public`] so public-admission paths can be exercised locally.
pub type SourceClassifier = Arc<dyn Fn(IpAddr) -> SourceClass + Send + Sync>;

/// Default classifier: [`SourceClass::of`].
pub fn default_classifier() -> SourceClassifier {
    Arc::new(SourceClass::of)
}

/// Key under which per-source state (rate buckets, bans, strikes) is kept.
///
/// IPv4 is used as-is. IPv6 is collapsed to its /64 prefix (low 64 bits zeroed):
/// one host or subscriber typically owns a whole /64, so keying on the full
/// address would let it dodge bans and rate limits by rotating addresses.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
}

fn is_private_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    // The shared helper also covers `0.0.0.0/8` and broadcast, which are not
    // private source ranges here (RFC 1918, loopback, link-local, CGNAT).
    v4.octets()[0] != 0 && !v4.is_broadcast() && dnscraft_common::net::is_private_v4(v4)
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local()
}

/// Client-ID presentation state after SNI / DoH path parsing.
#[derive(Clone, Debug, PartialEq, Eq)]

pub enum ClientIdState {
    /// No Client ID on the request.
    Absent,
    /// Registered in the policy snapshot.
    Registered(ClientId),
    /// Present but not registered.
    Unknown,
}

/// Result of [`Admission::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub enum AdmitDecision {
    /// Proceed to message handling.
    Admit,
    /// Drop silently (UDP) / close without a DNS answer (TCP).
    Drop {
        /// Stable `listeners.*` code.
        code: &'static str,
    },
    /// Answer with REFUSED / HTTP 429 (transport-specific).
    Refuse {
        /// Stable `listeners.*` code.
        code: &'static str,
    },
}

/// Whether a public Client-ID gate (SNI / DoH path) applies.
///
/// Only `(exposure Public, source Public)` requires a registered id. A private
/// source on a public listener behaves like local (id optional, unknown ignored).
pub fn public_client_id_required(exposure: Exposure, class: SourceClass) -> bool {
    exposure == Exposure::Public && class == SourceClass::Public
}

fn shard_index(key: IpAddr) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) & SOURCE_SHARD_MASK
}

fn shard_cap(total: usize) -> usize {
    total.div_ceil(SOURCE_SHARDS).max(1)
}

struct SourceShard {
    rate: TokenRate,
    sources: LruMap<IpAddr, TokenBucket>,
}

struct ClientBuckets {
    rate: TokenRate,
    clients: LruMap<ClientId, TokenBucket>,
}

/// Admission state: sharded rate buckets and a shared ban table.
///
/// Per-source state is keyed by [`source_key`] (IPv6 aggregated to /64) and
/// partitioned across [`SOURCE_SHARDS`] mutexes. Methods take `&self` so callers
/// share an `Arc<Admission>` without an outer mutex.
pub struct Admission {
    source_shards: Box<[Mutex<SourceShard>; SOURCE_SHARDS]>,
    clients: Mutex<ClientBuckets>,
    bans: Mutex<BanTable>,
    classify: SourceClassifier,
}

impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admission")
            .field("source_buckets", &self.source_bucket_count())
            .field("client_buckets", &self.client_bucket_count())
            .field("ban_entries", &self.ban_entry_count())
            .field("source_shards", &SOURCE_SHARDS)
            .finish_non_exhaustive()
    }
}

impl Admission {
    /// Builds empty tables from the validated config slices (default classifier).
    pub fn new(limits: &Limits, public: &PublicConfig) -> Self {
        Self::with_classifier(limits, public, default_classifier())
    }

    /// Like [`Self::new`] with an injectable source classifier.
    pub fn with_classifier(
        limits: &Limits,
        public: &PublicConfig,
        classify: SourceClassifier,
    ) -> Self {
        let cap = public.max_tracked_sources as usize;
        let per_shard = shard_cap(cap);
        let source_shards = std::array::from_fn(|_| {
            Mutex::new(SourceShard {
                rate: limits.rate_per_source,
                sources: LruMap::new(per_shard),
            })
        });
        Self {
            source_shards: Box::new(source_shards),
            clients: Mutex::new(ClientBuckets {
                rate: limits.rate_per_client_id,
                clients: LruMap::new(cap.max(1)),
            }),
            bans: Mutex::new(BanTable::new(
                cap,
                public.ban_strikes,
                public.ban_window,
                public.ban_duration,
            )),
            classify,
        }
    }

    /// Classifies `ip` with the installed classifier (after `to_canonical`).
    pub fn classify(&self, ip: IpAddr) -> SourceClass {
        (self.classify)(ip.to_canonical())
    }

    /// Applies a new limits/public config slice in place.
    ///
    /// Rate buckets are rebuilt empty (their transient token state belongs to the
    /// old rate), but the ban table is carried over: bans already in force keep
    /// their expiry, and the new ban params apply to new strikes only.
    pub fn reconfigure(&self, limits: &Limits, public: &PublicConfig) {
        let cap = public.max_tracked_sources as usize;
        let per_shard = shard_cap(cap);
        for shard in self.source_shards.iter() {
            let mut guard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.rate = limits.rate_per_source;
            guard.sources = LruMap::new(per_shard);
        }
        {
            let mut clients = self
                .clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            clients.rate = limits.rate_per_client_id;
            clients.clients = LruMap::new(cap.max(1));
        }
        self.bans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reconfigure(
                cap,
                public.ban_strikes,
                public.ban_window,
                public.ban_duration,
            );
    }

    /// Number of tracked source rate buckets (tests / status).
    pub fn source_bucket_count(&self) -> usize {
        self.source_shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .sources
                    .len()
            })
            .sum()
    }

    /// Number of tracked Client-ID rate buckets.
    pub fn client_bucket_count(&self) -> usize {
        self.clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clients
            .len()
    }

    /// Number of tracked ban/strike entries.
    pub fn ban_entry_count(&self) -> usize {
        self.bans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether a **public** source is currently banned (private → false).
    pub fn is_banned(&self, source: IpAddr, now: SystemTime) -> bool {
        let source = source.to_canonical();
        if self.classify(source) != SourceClass::Public {
            return false;
        }
        self.bans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_banned(source_key(source), now)
    }

    /// Currently banned sources (IPv6 as its /64 network address) with their ban expiry.
    pub fn banned_sources(&self, now: SystemTime) -> Vec<(IpAddr, SystemTime)> {
        self.bans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .banned(now)
    }

    /// Lifts the ban on `source`'s aggregation key; `true` when it was banned.
    pub fn unban(&self, source: IpAddr, now: SystemTime) -> bool {
        self.bans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unban(source_key(source), now)
    }

    /// Records a ban strike for a public source (no-op for private sources).
    pub fn strike(&self, source: IpAddr, reason: StrikeReason, now: SystemTime) {
        let source = source.to_canonical();
        if self.classify(source) != SourceClass::Public {
            return;
        }
        self.bans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .strike(source_key(source), reason, now);
    }

    /// Admission check for one query / connection attempt.
    ///
    /// Order: ban → public Do53 → public-listener Client ID → rate (source) →
    /// rate (Client ID for public sources).
    pub fn check(
        &self,
        listener: &ListenerConfig,
        source: IpAddr,
        client_id: &ClientIdState,
        now: SystemTime,
    ) -> AdmitDecision {
        let source = source.to_canonical();
        let class = self.classify(source);
        let proto = listener.protocol;
        let key = source_key(source);

        if class == SourceClass::Public
            && self
                .bans
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_banned(key, now)
        {
            // Spec: close immediately (no DNS answer on any transport).
            return AdmitDecision::Drop {
                code: "listeners.banned",
            };
        }

        if class == SourceClass::Public && matches!(proto, Protocol::Udp53 | Protocol::Tcp53) {
            return AdmitDecision::Drop {
                code: "listeners.admission.public_do53",
            };
        }

        if public_client_id_required(listener.exposure, class) {
            match client_id {
                ClientIdState::Registered(_) => {}
                ClientIdState::Absent | ClientIdState::Unknown => {
                    return AdmitDecision::Refuse {
                        code: "listeners.admission.unknown_client_id",
                    };
                }
            }
        }

        if !self.take_source(key, now) {
            return drop_or_refuse(proto, "listeners.rate_limited");
        }

        if class == SourceClass::Public
            && let ClientIdState::Registered(id) = client_id
            && !self.take_client(id, now)
        {
            return drop_or_refuse(proto, "listeners.rate_limited");
        }

        AdmitDecision::Admit
    }

    fn take_source(&self, source: IpAddr, now: SystemTime) -> bool {
        let mut shard = self.source_shards[shard_index(source)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bucket) = shard.sources.get_mut(&source) {
            return bucket.try_take(now);
        }
        let mut bucket = TokenBucket::new(shard.rate, now);
        let ok = bucket.try_take(now);
        shard.sources.insert(source, bucket);
        ok
    }

    fn take_client(&self, id: &ClientId, now: SystemTime) -> bool {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bucket) = clients.clients.get_mut(id) {
            return bucket.try_take(now);
        }
        let mut bucket = TokenBucket::new(clients.rate, now);
        let ok = bucket.try_take(now);
        clients.clients.insert(id.clone(), bucket);
        ok
    }
}

fn drop_or_refuse(proto: Protocol, code: &'static str) -> AdmitDecision {
    match proto {
        Protocol::Udp53 => AdmitDecision::Drop { code },
        Protocol::Tcp53 | Protocol::Dot | Protocol::Doh | Protocol::Doq => {
            AdmitDecision::Refuse { code }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::time::Duration;

    fn public_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
    }

    fn local_listener() -> ListenerConfig {
        ListenerConfig {
            node_id: None,
            nodes: Vec::new(),
            id: dnscraft_policy::ListenerId::new("test").unwrap(),
            protocol: Protocol::Udp53,
            address: "127.0.0.1:0".parse().unwrap(),
            exposure: Exposure::Local,
            h3: false,
            tls_policy: None,
        }
    }

    #[test]
    fn source_key_collapses_ipv6_to_slash_64_and_keeps_ipv4() {
        let v6: IpAddr = "2001:db8:1:2:dead:beef:0:1".parse().unwrap();
        assert_eq!(
            source_key(v6),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap(),
            "low 64 bits must be zeroed"
        );
        let v4 = public_ip();
        assert_eq!(source_key(v4), v4);
        let mapped: IpAddr = "::ffff:203.0.113.1".parse().unwrap();
        assert_eq!(source_key(mapped), v4, "IPv4-mapped uses the IPv4 key");
    }

    #[test]
    fn ipv6_ban_applies_to_whole_slash_64() {
        let public = PublicConfig {
            ban_strikes: 1,
            ..PublicConfig::default()
        };
        let adm = Admission::new(&Limits::default(), &public);
        let now = SystemTime::UNIX_EPOCH;
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let sibling: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other_net: IpAddr = "2001:db8:1:3::1".parse().unwrap();

        adm.strike(a, StrikeReason::UnknownClientId, now);
        assert!(adm.is_banned(sibling, now), "same /64 must share the ban");
        assert!(!adm.is_banned(other_net, now), "other /64 is unaffected");

        let banned = adm.banned_sources(now);
        assert_eq!(banned.len(), 1);
        assert_eq!(banned[0].0, "2001:db8:1:2::".parse::<IpAddr>().unwrap());

        assert!(adm.unban(sibling, now), "unban via any address in the /64");
        assert!(!adm.is_banned(a, now));
    }

    #[test]
    fn reconfigure_preserves_ban_table_and_applies_new_params_to_new_strikes() {
        let limits = Limits::default();
        let public = PublicConfig {
            ban_strikes: 1,
            ban_window: Duration::from_secs(60),
            ban_duration: Duration::from_secs(900),
            ..PublicConfig::default()
        };
        let adm = Admission::new(&limits, &public);
        let now = SystemTime::UNIX_EPOCH;
        let src = public_ip();

        adm.strike(src, StrikeReason::UnknownClientId, now);
        assert!(adm.is_banned(src, now), "single strike should ban");

        // Reconfigure with different ban params and admission rates.
        let limits2 = {
            let mut l = limits.clone();
            l.rate_per_source.per_second = 9999;
            l.rate_per_source.burst = 19998;
            l
        };
        let public2 = PublicConfig {
            ban_strikes: 5,
            ban_window: Duration::from_secs(120),
            ban_duration: Duration::from_secs(1800),
            ..PublicConfig::default()
        };
        adm.reconfigure(&limits2, &public2);

        // The existing ban survives with its expiry.
        assert!(adm.is_banned(src, now), "ban must survive reconfigure");
        assert_eq!(adm.ban_entry_count(), 1);

        // New ban params apply to new strikes: a fresh source needs 5, not 1.
        let src2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        adm.strike(src2, StrikeReason::UnknownClientId, now);
        assert!(
            !adm.is_banned(src2, now),
            "new ban_strikes=5 must apply to new strikes"
        );
    }

    #[test]
    fn concurrent_checks_across_distinct_sources_do_not_deadlock() {
        let limits = Limits {
            rate_per_source: TokenRate {
                per_second: 1_000_000,
                burst: 1_000_000,
            },
            ..Limits::default()
        };
        let adm = Arc::new(Admission::new(&limits, &PublicConfig::default()));
        let listener = Arc::new(local_listener());
        let now = SystemTime::UNIX_EPOCH;
        let threads = SOURCE_SHARDS * 2;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let adm = Arc::clone(&adm);
            let listener = Arc::clone(&listener);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 0..200 {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        10,
                        ((t * 17 + i) % 256) as u8,
                        ((t * 3 + i / 256) % 256) as u8,
                        ((t + i) % 254 + 1) as u8,
                    ));
                    let decision = adm.check(&listener, ip, &ClientIdState::Absent, now);
                    assert_eq!(decision, AdmitDecision::Admit);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("admission worker");
        }
        assert!(adm.source_bucket_count() > 0);
    }

    #[test]
    fn bans_remain_global_across_shards() {
        let public = PublicConfig {
            ban_strikes: 1,
            ..PublicConfig::default()
        };
        let adm = Admission::new(&Limits::default(), &public);
        let now = SystemTime::UNIX_EPOCH;
        // Distinct IPv4s land in different shards with high probability; ban
        // visibility must not depend on which shard holds the rate bucket.
        for i in 1..=32u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
            adm.strike(ip, StrikeReason::UnknownClientId, now);
            assert!(adm.is_banned(ip, now));
        }
        assert_eq!(adm.ban_entry_count(), 32);
    }
}
