# Anti-Cheat Product Metrics: What PMs Actually Measure

## Data Availability Honest Assessment

Anti-cheat metrics are **poorly standardized** across the industry. There is no equivalent of MITRE ATT&CK or NIST frameworks for measuring anti-cheat effectiveness. What we know comes from:

- **EA Javelin**: most transparent — publishes monthly metric reports for BF6 with specific numbers
- **Riot Vanguard**: moderately transparent — periodic dev blogs with before/after data, named metrics
- **Valve VAC/VACNet**: shared architecture details at GDC 2018, but limited ongoing metric disclosure
- **PUBG**: publishes semi-annual anti-cheat "dev letters" with ban counts and trend data
- **BattlEye / EAC**: almost no public metrics — private B2B products, metrics shared only with studio clients
- **Bungie**: explicitly stated "we don't have any specific numbers to share"

Most studios do NOT publish anti-cheat metrics. What follows is assembled from the studios that do, supplemented with industry research. **Where data doesn't exist publicly, I say so.**

## Tier 1: Detection & Enforcement Metrics

These are the operational metrics the AC team measures day-to-day.

### Match Infection Rate (MIR) — EA Javelin's Primary Metric

**Definition**: the percentage of matches where at least one cheater impacted gameplay.

**How calculated**: every match containing a confirmed cheater (banned) OR suspected cheater (flagged by detection signals but insufficient evidence for ban) is marked "infected." MIR = infected matches / total matches.

**Key nuance**: MIR is a **retrospective metric that matures over time**. Initial readings are preliminary; as more detections/bans accumulate, past matches get reclassified. EA's December 31 MIR was initially 3.09%, later matured to 2.28%.

**Published values**:
- BF6 Open Beta start (Aug 7, 2025): ~7% MIR
- BF6 Open Beta end (Aug 17, 2025): ~2% MIR
- BF6 launch week (Oct 2025): ~2% MIR
- BF6 January 2026: 2.28-3.60% range

**What MIR does well**: measures player experience impact, not just detection volume. A player cares about "how often will I encounter a cheater," not "how many cheats did you detect globally."

**What MIR doesn't capture**: severity of cheating (a wallhack-only cheater and a rage aimbotter both count as one infection), whether the cheater was on your team or enemy team, how many rounds the cheater ruined before detection.

Sources: [EA BF6 Season 1 Update](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1), [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january)

### Time-to-Action (TTA) — Riot's Primary Metric

**Definition**: the number of games a cheater is able to play before their account is banned.

**Published values**:
- Pre-Vanguard (LoL): 45+ games before ban
- Post-Vanguard (LoL): fewer than 10 games before ban
- Valorant: average cheater banned within 6 games

**Why it matters**: every game the cheater plays before ban is a game ruined for 9 other players (in a 5v5). Reducing TTA from 45 to 10 means ~35 fewer ruined matches per cheater.

**Design tension**: Riot deliberately introduces **strategic delay** into bans. Banning immediately after detection reveals the detection method to cheat developers, who can then update their cheat to avoid it. A delay keeps detections valid longer but means more matches are impacted. This is an explicit product trade-off.

Sources: [Riot: Vanguard x LoL Retrospective](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol-retrospective/), [Riot: Anti-Cheat in LoL](https://www.leagueoflegends.com/en-us/news/dev/dev-anti-cheat-in-lol-more/)

### Time-to-Detection (TTD) — Riot's Secondary Metric

**Definition**: how long a new cheat (or cheat update) operates in the ecosystem before a detection is created.

**Published values**: Riot acknowledges this metric but does not publish specific numbers. They note it is "currently rapid but expected to increase as cheats become more sophisticated."

**Why it matters**: TTD measures the AC team's responsiveness to new threats. A cheat that evades detection for 30 days infects many more matches than one detected in 24 hours.

**No other studio publishes a TTD-equivalent metric publicly.**

Source: [Riot: Vanguard x LoL Retrospective](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol-retrospective/)

### Cheater Prevalence Rate

**Definition**: percentage of matches (or ranked matches) containing at least one cheater.

**Published values**:
- Riot (LoL post-Vanguard): ranked scripting rate below 1% — 1 in 200 ranked games. Down from ~1 in 50 pre-Vanguard.
- Riot (Valorant): fewer than 1% of ranked games globally contain cheaters
- EA (BF6): ~2% MIR (similar concept)

**No standard definition**: Riot counts scripters, EA counts all cheat types. These are not directly comparable.

### Ban Accuracy Rate

**Definition**: percentage of bans that are correct (not false positives).

**Published values**:
- EA Javelin: >99% accuracy
- Riot Vanguard: false positive rate sub 0.01% (less than 1 false positive per 10,000 bans)

**Why it matters enormously**: a 99% ban accuracy rate sounds great until you realize that at scale (millions of bans), 1% means tens of thousands of wrongfully banned players. Each wrongful ban is a customer who paid money for game content and lost access.

Valve historically delayed bans until they were "100% sure" specifically because of the customer satisfaction implications — banned players lost access to content they paid real money for.

**Riot's false positive handling**: average suspension duration for false positives under 72 hours. Majority of unbans are for stolen accounts (the account owner wasn't cheating; the account thief was).

Sources: [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report), [Riot: Vanguard x LoL Retrospective](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol-retrospective/)

### Cheat Attempts Blocked (Volume)

**Definition**: raw count of cheat attempts prevented by the AC system.

**Published values**:
- EA Javelin (lifetime since Sept 2022): 33M+ across 2.2B sessions
- EA Javelin (BF6 beta): 1.2M+
- EA Javelin (BF6 launch weekend): 367K
- EA Javelin (BF6 January 2026): 384,918
- PUBG (H1 2024): 1,480,434 permanent bans
- PUBG (Jan-Nov 2025): ~7.81M permanent bans

**Limitations**: raw volume is a vanity metric without context. 33M blocked attempts across 2.2B sessions means ~1.5% of sessions had a cheat attempt — but does that mean the cheats were caught, or that 1.5% of players tried to cheat? The metric conflates "blocks" (real-time prevention) with "bans" (post-detection enforcement).

Sources: [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report), [PUBG Dev Letter 2025](https://www.pubg.com/en/news/9634)

## Tier 2: Ecosystem Disruption Metrics

These measure impact on the cheat supply chain, not just individual cheaters.

### Cheat Program Tracking & Disruption Rate

**Definition**: number of known cheat programs/vendors being tracked, and what percentage have been disrupted (reporting failures, going offline, or shutting down).

**Published values (EA Javelin, BF6)**:
- Season 1: tracking 190 programs/vendors, 183 (96.3%) reporting failures or takedowns
- January 2026: tracking 224 programs/vendors, 212 (94.64%) disrupted

**What "disrupted" means**: the cheat seller has announced feature failures, detection notices, downtime, or taken their cheat offline. This does NOT mean the cheat is permanently dead — many come back after updates.

**Why this matters for a PM**: this measures whether the AC is winning the arms race at the supply-chain level, not just detecting individual users. If 95% of cheat sellers are struggling, the market contracts.

**No other studio publishes this metric publicly.** This is unique to EA's BF6 reporting and is arguably their most interesting metric from a product strategy perspective.

Source: [EA BF6 Season 1 Update](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1), [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january)

### Cheat Market Pricing as a Signal

**Not a published metric by any studio**, but discussed in industry research as an indirect measure of AC effectiveness.

Logic: if the AC is effective, cheat development becomes harder, which increases cheat prices. Cheat subscriptions range from $10/month (games with weak AC) to $200+/month (games with strong kernel AC like Valorant). If prices are rising for cheats targeting your game, your AC is working.

The global cheat economy is estimated at $8.5B (cheat software subscriptions: $3.5B, related services: $5B), with per-cheat annual revenues estimated between $12.8M and $73.2M.

Sources: [SecurityBrief: Video game cheat economy](https://securitybrief.co.uk/story/video-game-cheat-economy-grows-into-usd-8-5bn-giant), [Anti-Cheat PD on X](https://x.com/AntiCheatPD/status/1851400983194091648)

### Legal Enforcement Metrics

**Published values (PUBG)**:
- Through September 2025: ~$1,713,823 confiscated through legal actions
- 30,000+ cheat programs blocked via legal/takedown efforts

**Why this matters**: some studios (PUBG, Bungie, Riot) pursue legal action against cheat developers. The financial impact on cheat sellers is a product-level metric of ecosystem disruption.

Source: [PUBG Dev Letter 2025](https://www.pubg.com/en/news/9634)

## Tier 3: Operational & Technical Metrics

These are internal engineering metrics, mostly NOT publicly reported.

### Detection Time Reduction

**Published values (PUBG)**:
- AI-based detection framework increased detection rate by ~2.5x
- Reduced detection time by 90%
- Review processing time dropped ~75%
- Monitoring staff increased 2.8x

This is the clearest published example of internal operational improvement metrics.

Source: [PUBG Dev Letter 2025](https://www.pubg.com/en/news/9634)

### VACNet Conviction Rate — Valve's ML Metric

**Definition**: when VACNet's ML model flags a player and submits the case for review, how often is a conviction reached?

**Published values (GDC 2018)**:
- Human (Overwatch) submissions: 15-30% conviction rate
- VACNet submissions: 80-95% conviction rate

**Architecture**: VACNet analyzes sequences of 140 shots across an 8-round window. Runs across ~3,500 processors, scanning ~150,000 daily CS:GO matches. Trained on human Overwatch investigator conviction data.

**Why this matters**: it measures ML model precision. A high conviction rate means the model is highly selective — few false flags. This is the only published example of an AC vendor sharing their ML model's performance characteristics.

Source: [GDC 2018: VACNet](https://d3.harvard.edu/platform-rctom/submission/valve-using-machine-learning-and-deep-learning-to-catch-cheaters-on-csgo-794-words/), [PC Gamer: VACNet](https://www.pcgamer.com/vacnet-csgo/)

### Performance Overhead

**Definition**: FPS/CPU impact of the anti-cheat on game performance.

**Published values**: EA claims "negligible impact on gameplay" for Javelin. Industry benchmarks suggest kernel-level ACs cause 3-7% FPS drop on average, though idle impact is negligible on modern CPUs.

**Known issues**: Javelin interferes with AMD X3D CPUs' automatic core parking, causing unexpected performance degradation on a specific (popular) hardware configuration. This is the kind of metric a PM needs to track — platform-specific performance regressions.

Sources: [LoadSyn: Javelin vs Vanguard FPS](https://loadsyn.com/kernel-anticheat-javelin-vanguard-fps-benchmark/), [DTpTips: Javelin AMD X3D](https://dtptips.com/%F0%9F%A7%A0-eas-javelin-anti-cheat-is-hurting-amds-x3d-cpus-heres-why-it-happens-and-what-you-can-do/)

### Bot Suppression (Riot-specific)

**Published values**:
- Pre-Vanguard: bots consuming >1M game hours per day
- Post-Vanguard: <5,000 hours per day
- 3.5M bot accounts purged post-launch

Source: [Riot: Vanguard x LoL Retrospective](https://www.leagueoflegends.com/en-us/news/dev/dev-vanguard-x-lol-retrospective/)

## Tier 4: Business Impact Metrics

These connect anti-cheat to business outcomes. **No studio publishes these directly tied to anti-cheat**, but industry research establishes the relationship.

### Player Retention / Churn Due to Cheating

**Published survey data (Atomik Research / PlaySafe ID, July 2025, n=2,013)**:
- 80% of gamers have encountered cheating in online games
- 42% have considered quitting a game entirely because of cheaters
- 83% would be more likely to play a game credibly promoted as cheat-free
- 73% comfortable with identity verification to ensure cheat-free experiences

Source: [PlaySafe ID Survey](https://www.gamespress.com/GAMINGS-CHEATING-CRISIS-REVEALED-IN-FULL-BY-PLAYSAFE-ID)

### Revenue Impact

**Published survey data**:
- 55% of gamers reduced or stopped in-game purchases due to cheating
- 17% stopped ALL spending in games where they encountered cheating
- 38% reduced their spending
- Estimated $29B of revenue at risk if 78% of gamers are deterred by cheating

Source: [PlaySafe ID Survey](https://www.gamespress.com/GAMINGS-CHEATING-CRISIS-REVEALED-IN-FULL-BY-PLAYSAFE-ID), [Irdeto: Anti-cheat in video games](https://irdeto.com/blog/cheating-in-games-everything-you-always-wanted-to-know-about-it)

### Secure Boot Adoption (Platform Metric)

**Published values (EA Javelin)**:
- BF6 Open Beta start: 62.5% of players had Secure Boot enabled
- BF6 Open Beta end: 92.5% enabled Secure Boot to play
- Current: 98.5% of players can activate Secure Boot

This is a unique operational metric: it measures the anti-cheat's ability to shift the security posture of its install base. Javelin effectively got ~30% of its player base to enable a security feature they hadn't bothered with before.

Source: [EA BF6 Season 1 Update](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1)

## What's NOT Publicly Measured (Gaps)

These are metrics you'd expect a PM to want, but no studio publishes:

| Metric | Why It's Missing |
|--------|------------------|
| **Detection coverage rate** (% of known cheat techniques detected) | Revealing gaps helps cheat devs |
| **Zero-day cheat survival time** | Closely guarded operational intelligence |
| **Revenue directly attributable to AC** | Hard to isolate; AC is one of many factors in retention |
| **Player trust/sentiment index for AC specifically** | Studios survey this internally but don't publish |
| **Cost per detection/ban** | Internal operational cost accounting |
| **Ranked rollback frequency** | Riot's feature to undo RR lost to cheaters; no public data on how often it triggers |
| **AC-caused crashes/BSODs** | No studio publishes reliability data for their kernel driver |
| **False positive rate by detection type** | Would reveal which detections are weakest |
| **Cheat recidivism rate** | How often banned players return on new accounts |

## Proposed Metric Framework for a PM Interview

If asked "how would you measure anti-cheat effectiveness?" in an interview, structure the answer in concentric rings:

### Ring 1: Player Experience (what the player feels)
- **Match Infection Rate** — % of matches impacted by cheaters
- **Perceived fairness score** — survey-based, sentiment tracking
- **Ranked integrity** — are rankings trustworthy? (hard to measure directly)

### Ring 2: Operational Effectiveness (how well the AC works)
- **Time-to-Detection** — how fast new cheats are identified
- **Time-to-Action** — how many games before ban
- **Ban accuracy** — false positive rate
- **Detection coverage** — % of known cheat techniques covered (internal)

### Ring 3: Ecosystem Impact (are we winning the arms race?)
- **Cheat supply disruption rate** — % of tracked cheat sellers disrupted
- **Cheat pricing trends** — are cheats for our game getting more expensive?
- **New cheat emergence rate** — how often do new cheats appear?

### Ring 4: Business Outcomes (does AC affect the bottom line?)
- **Retention correlation** — player retention in regions/modes with high vs low cheat prevalence
- **Revenue per user** — spending patterns in clean vs infected matches
- **DAU/MAU impact** — does a ban wave increase engagement? (A/B testable)
- **Support ticket volume** — cheat-related complaint rate as % of total

### Ring 5: Technical Health (is the AC itself healthy?)
- **Performance overhead** — FPS impact, CPU usage
- **Crash/BSOD rate** — reliability of the kernel driver
- **Update deployment success rate** — do signature updates cause issues?
- **Platform coverage** — what % of the player base can run the AC? (Secure Boot adoption)
