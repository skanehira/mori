use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ip: Ipv4Addr,
    pub expires_at: Instant,
}

#[derive(Default, Debug)]
pub struct UpdateDiff {
    pub added: Vec<Ipv4Addr>,
    pub removed: Vec<Ipv4Addr>,
}

#[derive(Default, Debug)]
pub struct DnsCache {
    per_domain: HashMap<String, HashMap<Ipv4Addr, Instant>>,
}

impl DnsCache {
    pub fn apply(&mut self, domain: &str, now: Instant, entries: Vec<Entry>) -> UpdateDiff {
        let state = self.per_domain.entry(domain.to_string()).or_default();

        let mut new_state: HashMap<Ipv4Addr, Instant> = HashMap::new();
        for entry in entries {
            if entry.expires_at <= now {
                continue;
            }
            new_state
                .entry(entry.ip)
                .and_modify(|expires| {
                    if *expires < entry.expires_at {
                        *expires = entry.expires_at;
                    }
                })
                .or_insert(entry.expires_at);
        }

        let mut removed: Vec<Ipv4Addr> = state
            .keys()
            .filter(|ip| !new_state.contains_key(ip))
            .copied()
            .collect();

        let mut added: Vec<Ipv4Addr> = new_state
            .keys()
            .filter(|ip| !state.contains_key(ip))
            .copied()
            .collect();

        *state = new_state;

        removed.sort();
        removed.dedup();
        added.sort();
        added.dedup();

        UpdateDiff { added, removed }
    }

    pub fn next_refresh_in(&self, now: Instant) -> Option<Duration> {
        self.per_domain
            .values()
            .flat_map(|ips| ips.values())
            .map(|expires| expires.saturating_duration_since(now))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn adds_new_ips() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        let entry = Entry {
            ip: Ipv4Addr::new(192, 168, 0, 1),
            expires_at: now + Duration::from_secs(60),
        };

        let diff = cache.apply("example.com", now, vec![entry.clone()]);

        assert_eq!(diff.added, vec![entry.ip]);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn expires_old_ips() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        let entry = Entry {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            expires_at: now + Duration::from_secs(30),
        };
        cache.apply("example.com", now, vec![entry.clone()]);

        let later = now + Duration::from_secs(45);
        let diff = cache.apply("example.com", later, vec![]);

        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![entry.ip]);
    }

    #[test]
    fn next_refresh_tracks_soonest_expiry() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        cache.apply(
            "example.com",
            now,
            vec![Entry {
                ip: Ipv4Addr::new(1, 1, 1, 1),
                expires_at: now + Duration::from_secs(5),
            }],
        );
        cache.apply(
            "example.net",
            now,
            vec![Entry {
                ip: Ipv4Addr::new(2, 2, 2, 2),
                expires_at: now + Duration::from_secs(10),
            }],
        );

        let refresh = cache.next_refresh_in(now).expect("has entries");
        assert_eq!(refresh, Duration::from_secs(5));
    }
}
