question: We are building "ArenaOS" — a cross-game competitive gaming platform. We host an MMORPG ("DragonKeep") and a 5v5 tactical shooter ("VaultRun"). We need guild
  permission hierarchies (Guild Leader down to Recruit, with a guild bank that different ranks can access differently), tournament bracket access that follows team
  advancement (eliminated teams lose access, advancing teams unlock next-round resources), and tiered spectator access (public, registered, VIP, streamers, private invite-only
  matches). We also need short-lived match session tokens so our anti-cheat system can validate every action. Walk us through the whole thing.

● Gaming is the fastest-moving auth scenario there is. Guild ranks change hourly. Tournament brackets resolve in minutes. Spectators spike from zero to millions. Session tokens
  expire in 30 minutes. The auth layer needs to handle all of this without the application re-architecting every time a new guild feature ships.

  The pattern that makes this work: guilds and tournament brackets are Zanzibar objects, not orgs. Orgs give you the ceiling ("you are a DragonKeep player"). Zanzibar gives you
  the real-time relationship ("you are an Officer in IronCrest guild with deposit rights up to 500 gold, and right now you are the lead-tank in tonight's raid"). Membership
  changes, rank promotions, and bracket eliminations are all tuple writes — no token re-issue, no cache bust, immediate effect.

  By the end you'll have:

  - A platform / game tenant org structure
  - Guild namespaces with 5 ranks, each with different guild bank access
  - Probationary recruit system — join the guild, prove yourself, earn full membership
  - Tournament bracket tree: access follows team advancement, eliminated teams cut off
  - Four spectator tiers: public, registered, VIP (paid), and streamer delegation tokens
  - Private match invite-only spectating
  - Match session tokens: 30-minute, match-scoped, validated by anti-cheat
  - Service API keys: matchmaking, anti-cheat, leaderboard, streaming relay

  ---
  Concept: Why Guilds Are Not Orgs

  A game like DragonKeep can have 50,000 active guilds. Each guild has 10–500 members.
  Members join, leave, get promoted, get kicked, transfer servers, and go inactive. Creating
  a child org per guild would work, but:

  - 50,000 child orgs under DragonKeep creates deep hierarchy overhead
  - Kicking a player from a guild requires org membership removal, which affects their
    JWT and requires a re-login mid-session — not acceptable in an active game
  - Rank changes (Member → Officer) in an org model require role updates, which also
    touch the token. In Zanzibar, a rank change is one tuple delete + one tuple write,
    with zero token impact. The player's next action just gets a different check result.
  - Tournament brackets are even more transient — a bracket object lives for 45 minutes

  Guilds and brackets are Zanzibar objects. The game org (DragonKeep) is where players
  live. The guild/bracket layer is where their in-game relationships live.

  ---
  Concept: Tournament Brackets as Authorization Objects

  Tournament access is naturally tree-shaped:

  tournament:vaultrun-open-s3
  ├── bracket:qf-1  (NovaBurst vs GhostPulse)
  ├── bracket:qf-2  (IronWall vs CryptoBlaze)
  ├── bracket:sf-1  (winner of qf-1 vs winner of qf-2)
  ├── bracket:sf-2  (winner of qf-3 vs winner of qf-4)
  └── bracket:grand-final

  When NovaBurst wins qf-1, the matchmaking service writes one tuple:
  bracket:sf-1 #participant org:novabursteports#member

  NovaBurst now has access to sf-1 resources (strategy tools, comms channel, warm-up lobby).
  GhostPulse does not — they were eliminated, no tuple written for them on sf-1.

  No application code checks "which round is this team in" — Zanzibar does it.

  ---
  The Architecture: ArenaOS

  ArenaOS (platform org — Sofia Chen, platform engineering)
  │
  ├── [CHILD ORG] DragonKeep              (MMORPG — guilds, raids, PvP)
  │   ├── Members: all DragonKeep players (role: player)
  │   └── Zanzibar objects: guild:*, raid:*, dungeon:*, server:*
  │
  └── [CHILD ORG] VaultRun               (5v5 shooter — ranked, tournaments, esports)
      ├── Members: all VaultRun players (role: player)
      ├── [CHILD ORG] NovaBurst Esports   (registered esports org)
      │   └── Members: 5 roster players + coach + analyst
      ├── [CHILD ORG] GhostPulse Esports  (another registered esports org)
      └── Zanzibar objects: tournament:*, bracket:*, match:*, spectator_room:*

  Characters:
  - Sofia Chen          — ArenaOS CTO (platform owner)
  - Magnus Veil         — DragonKeep player, IronCrest Guild Leader
  - Lyra Stonewind      — IronCrest Officer (recruitment lead)
  - Kira Dawnblade      — IronCrest Officer (raid coordinator)
  - Ash                 — IronCrest Member (veteran player)
  - Pixel               — IronCrest Recruit (probationary, joined last week)
  - Team NovaBurst      — 5 VaultRun players: Riven, Flux, Zen, Nova, Echo
  - Coach Petra         — NovaBurst coach (spectator with team comms access)
  - Ref. Sarah Park     — Tournament judge
  - TwitchCast Bot      — Streaming service (delegation token, broadcast rights)
  - Viewers (public)    — Anonymous or logged-in spectators

  ---

## Step 1: Platform Setup

  Sofia creates the ArenaOS platform and registers the two games as child orgs:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/register                                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "email": "sofia@arenaos.gg", "password": "...", "name": "Sofia Martinez", "org_name": "ArenaOS", "org_slug": "arenaos" }

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations  (two calls)                                              │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "name": "DragonKeep", "slug": "dragonkeep", "parent_id": "org_arenaos",
    "settings": { "default_role": "player", "invitation_only": false } }

  { "name": "VaultRun", "slug": "vaultrun", "parent_id": "org_arenaos",
    "settings": { "default_role": "player", "invitation_only": false } }

  Now define the permission schema across the platform:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /permissions/registry/register  (one call per service)                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Game service permissions
  { "service": "game", "description": "Core gameplay permissions",
    "actions": ["play", "read"], "resources": ["stats", "replays"] }

  // Guild service permissions
  { "service": "guild", "description": "Guild management permissions",
    "actions": ["read", "write", "manage"], "resources": ["roster", "bank"] }

  // Tournament service permissions
  { "service": "tournament", "description": "Tournament lifecycle permissions",
    "actions": ["participate", "officiate", "organize"], "resources": [] }

  // Match service permissions
  { "service": "match", "description": "Live match permissions",
    "actions": ["spectate", "read"], "resources": ["live_stats", "comms"] }

  // Platform service permissions
  { "service": "platform", "description": "Platform administration",
    "actions": ["manage"], "resources": [] }

  Custom roles for gaming contexts:

  // Regular player — plays the game, sees their stats
  { "name": "player",        "permissions": ["game.play", "game.read.stats", "match.spectate"] }

  // Esports org member — player with tournament rights
  { "name": "esports_player","permissions": ["game.play", "game.read.stats", "game.read.replays",
                                             "match.spectate", "tournament.participate"] }

  // Tournament referee — officiates matches, no playing
  { "name": "referee",       "permissions": ["tournament.officiate", "match.spectate",
                                             "match.read.live_stats", "match.read.comms"] }

  // Tournament organizer — runs the whole event
  { "name": "organizer",     "permissions": ["tournament.organize", "tournament.officiate",
                                             "match.spectate", "match.read.live_stats",
                                             "match.read.comms"] }

  What just happened?
  ─────────────────
  Players in DragonKeep and VaultRun register via the org's public login page and land with
  role "player" — game.play and basic stats/spectate access. Guild leadership and tournament
  participation are Zanzibar relations, not org roles. The "player" role is the floor; Zanzibar
  defines the ceiling for any specific guild, match, or bracket object.

---

## Step 2: The Zanzibar Guild Schema

  Before Magnus can create IronCrest, the platform needs guild namespaces:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_dragonkeep/namespaces                              │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Guild — the main guild object
  {
    "name": "guild",
    "relations": {
      "guild_leader":  {},
      "officer":       {},
      "member":        {},
      "recruit":       {},

      // computed: who can manage the guild at all
      "leadership":    { "union": ["guild_leader", "officer"] },
      // computed: who is "in" the guild (any rank)
      "roster":        { "union": ["guild_leader", "officer", "member", "recruit"] }
    },
    "permissions": {
      "disband":          { "relation": "guild_leader" },
      "promote_officer":  { "relation": "guild_leader" },
      "kick_member":      { "relation": "leadership" },
      "invite_recruit":   { "relation": "leadership" },
      "schedule_raid":    { "union": ["guild_leader", "officer"] },
      "rsvp_raid":        { "relation": "roster" },
      "view_roster":      { "relation": "roster" },
      "view_officer_chat":{ "relation": "leadership" }
    }
  }

  // Guild bank — a separate object from the guild itself
  {
    "name": "guild_bank",
    "relations": {
      "full_access":        {},
      "deposit_only":       {},
      "view_only":          {}
    },
    "permissions": {
      "deposit":   { "union": ["full_access", "deposit_only"] },
      "withdraw":  { "relation": "full_access" },
      "view_log":  { "union": ["full_access", "deposit_only", "view_only"] }
    }
  }

  // Raid event — a scheduled group activity
  {
    "name": "raid",
    "relations": {
      "raid_leader":    {},
      "confirmed_slot": {},
      "standby":        {},
      "can_view":       { "union": ["raid_leader", "confirmed_slot", "standby"] }
    },
    "permissions": {
      "lead":            { "relation": "raid_leader" },
      "view_strategy":   { "relation": "can_view" },
      "confirm_signup":  { "relation": "raid_leader" }
    }
  }

  // Tournament match — a live game between two teams
  {
    "name": "match",
    "relations": {
      "participant":     {},
      "referee":         {},
      "vip_spectator":   {},
      "spectator":       {},
      "streamer":        {},
      "invited_viewer":  {},
      "public":          {}
    },
    "permissions": {
      "play":             { "relation": "participant" },
      "officiate":        { "relation": "referee" },
      "view_live":        { "union": ["participant", "referee", "vip_spectator",
                                      "spectator", "streamer", "invited_viewer", "public"] },
      "view_live_stats":  { "union": ["participant", "referee", "vip_spectator", "streamer"] },
      "view_team_comms":  { "union": ["participant", "referee"] }
    }
  }

  // Tournament bracket — one round in the bracket tree
  {
    "name": "bracket",
    "relations": {
      "participant":  {},
      "organizer":    {},
      "referee":      {}
    },
    "permissions": {
      "access_resources": { "union": ["participant", "organizer", "referee"] },
      "advance_winner":   { "union": ["organizer", "referee"] }
    }
  }

  What just happened?
  ─────────────────
  The guild_bank is a separate Zanzibar object from the guild itself. This matters because
  different ranks have different bank access — and those rules should live in Zanzibar, not
  in application code that might have edge cases. The "guild" and "guild_bank" objects
  are linked by writing tuples with the guild's leadership relations on the bank object.

  The match namespace has a "public" relation with the wildcard subject (user:*). When a
  match is set to public spectating, one tuple enables all authenticated users to watch.
  One tuple write switches the match from private to public — no loop over spectators.

---

## Step 3: Magnus Creates IronCrest Guild

  Magnus has been playing DragonKeep for two years. He decides to form his own guild:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /guilds                                                                  │
  │  Authorization: Bearer eyJ...  (Magnus's player token)                        │
  │  X-Org-Id: org_dragonkeep                                                     │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "name":   "IronCrest",
    "tag":    "IRC",
    "motto":  "Forged in fire. Tempered in battle.",
    "server": "Ashenvale-7"
  }

  Response:
  {
    "guild_id":  "guild_ironcrest",
    "bank_id":   "guild_bank_ironcrest",
    "name":      "IronCrest",
    "founder":   "usr_magnus"
  }

  The platform writes the founding Zanzibar tuples:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_dragonkeep/relationships  (internal, called by guild service) │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Magnus is the guild leader
  { "object": "guild:guild_ironcrest",      "relation": "guild_leader", "subject": "user:usr_magnus" }

  // Magnus has full access to the guild bank (leader can deposit, withdraw, view log)
  { "object": "guild_bank:guild_bank_ironcrest", "relation": "full_access", "subject": "user:usr_magnus" }

  What just happened?
  ─────────────────
  Two objects were created simultaneously: the guild and its bank. The bank is a first-class
  Zanzibar object. Its access rules are completely separate from guild membership. A player
  could theoretically be a member of the guild but have no bank access (a new recruit), or
  have bank access without being a named officer (a trusted veteran given special rights).

  Zanzibar checks after founding:
  Can usr_magnus disband guild:guild_ironcrest?         → guild_leader → YES
  Can usr_magnus withdraw from guild_bank_ironcrest?    → full_access → YES
  Can usr_magnus schedule_raid on guild:guild_ironcrest?→ guild_leader → leadership → YES

---

## Step 4: Building the Guild — Officers, Members, Bank Access

  Magnus invites Lyra and Kira as officers. Officers in IronCrest are expected to help run
  the guild, but Magnus sets different bank access levels for each:

  Lyra (recruitment officer — handles applicants, doesn't need bank access):
  { "object": "guild:guild_ironcrest",          "relation": "officer",      "subject": "user:usr_lyra" }
  { "object": "guild_bank:guild_bank_ironcrest","relation": "deposit_only", "subject": "user:usr_lyra" }

  Kira (raid coordinator — manages consumables from bank, needs withdrawal rights):
  { "object": "guild:guild_ironcrest",          "relation": "officer",      "subject": "user:usr_kira" }
  { "object": "guild_bank:guild_bank_ironcrest","relation": "full_access",  "subject": "user:usr_kira" }

  Ash joins as a regular member — no bank access yet:
  { "object": "guild:guild_ironcrest",          "relation": "member",       "subject": "user:usr_ash" }
  { "object": "guild_bank:guild_bank_ironcrest","relation": "view_only",    "subject": "user:usr_ash" }

  Zanzibar checks:
  Can usr_lyra withdraw from guild_bank_ironcrest?  → deposit_only → NO (withdraw requires full_access)
  Can usr_lyra deposit to guild_bank_ironcrest?     → deposit_only → YES
  Can usr_kira withdraw from guild_bank_ironcrest?  → full_access → YES
  Can usr_ash view_log of guild_bank_ironcrest?     → view_only → YES
  Can usr_ash withdraw from guild_bank_ironcrest?   → view_only → NO

  What just happened?
  ─────────────────
  Two officers with identical guild rank have different bank permissions. This is not a
  custom sub-role. It's two separate Zanzibar tuples on the bank object. Guild rank and
  bank access are independently configurable. Magnus didn't need to create a new role
  or ask Lyra to re-login. He wrote two tuples.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Guild bank permission matrix:                                                  │
  ├────────────────────────────┬────────────┬────────────┬───────────┬─────────────┤
  │  Bank relation             │  Magnus    │  Kira      │  Lyra     │  Ash        │
  ├────────────────────────────┼────────────┼────────────┼───────────┼─────────────┤
  │  full_access               │    YES     │    YES     │    NO     │     NO      │
  ├────────────────────────────┼────────────┼────────────┼───────────┼─────────────┤
  │  deposit_only              │    —       │    —       │    YES    │     NO      │
  ├────────────────────────────┼────────────┼────────────┼───────────┼─────────────┤
  │  view_only                 │    —       │    —       │    —      │     YES     │
  ├────────────────────────────┼────────────┼────────────┼───────────┼─────────────┤
  │  Effective: withdraw       │    YES     │    YES     │    NO     │     NO      │
  ├────────────────────────────┼────────────┼────────────┼───────────┼─────────────┤
  │  Effective: deposit        │    YES     │    YES     │    YES    │     NO      │
  ├────────────────────────────┼────────────┼────────────┼───────────┼─────────────┤
  │  Effective: view_log       │    YES     │    YES     │    YES    │     YES     │
  └────────────────────────────┴────────────┴────────────┴───────────┴─────────────┘

---

## Step 5: Recruit Probation — Pixel Applies to IronCrest

  Pixel has been on the server for two months and wants to join IronCrest. They apply through
  the guild finder. Lyra reviews and accepts them as a Recruit:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /guilds/guild_ironcrest/members                                         │
  │  Authorization: Bearer eyJ...  (Lyra's officer token)                         │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "user_id": "usr_pixel", "rank": "recruit" }

  Zanzibar tuples written:
  { "object": "guild:guild_ironcrest", "relation": "recruit", "subject": "user:usr_pixel" }
  (No bank tuple — recruits don't get bank access)

  Pixel's in-game experience as a Recruit:
  Can usr_pixel view_roster of guild:guild_ironcrest?   → recruit → roster computed → YES
  Can usr_pixel rsvp_raid on guild:guild_ironcrest?     → recruit → roster computed → YES
  Can usr_pixel view_officer_chat on guild:guild_ironcrest? → officer/leader only → NO
  Can usr_pixel invite_recruit to guild:guild_ironcrest?    → leadership only → NO
  Can usr_pixel view guild_bank_ironcrest at all?       → no tuple on bank → NO

  Pixel can see who's in the guild and RSVP to raids. They cannot invite others, access the
  bank, or see officer communications. The recruit rank limits their view — not through
  complex permission logic, but through the absence of bank tuples and the officer_chat
  permission requiring the leadership computed relation.

  Two weeks later, Ash vouches for Pixel. Magnus promotes them to Member:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_dragonkeep/relationships/swap  (atomic tuple replace) │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "remove": { "object": "guild:guild_ironcrest", "relation": "recruit", "subject": "user:usr_pixel" },
    "add":    { "object": "guild:guild_ironcrest", "relation": "member",  "subject": "user:usr_pixel" }
  }

  // Also grant bank view access
  { "object": "guild_bank:guild_bank_ironcrest", "relation": "view_only", "subject": "user:usr_pixel" }

  Pixel's game client sends their next action. The Zanzibar check fires. Pixel now has member
  access. No re-login. No new token. The relationship changed; the check result changed.

  What just happened?
  ─────────────────
  The atomic swap is critical. If you delete the recruit tuple and then the server crashes
  before writing the member tuple, Pixel has zero guild access — they'd be locked out of
  their own guild page until someone notices. The swap writes both changes together. Either
  both succeed, or neither does. Zanzibar tuples are the authoritative state; the game
  database follows.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "Magnus wants to kick a toxic player who's been officer for a year.│
  │  They have dozens of guild tuples. How do we clean up completely?"             │
  │                                                                                 │
  │  1. Query all relationships for the user on this guild:                        │
  │     POST /zanzibar/stores/org_dragonkeep/list-objects                         │
  │     { "subject": "user:usr_toxic", "permission": "roster", "object_type": "guild" }│
  │     POST /zanzibar/stores/org_dragonkeep/list-objects                         │
  │     { "subject": "user:usr_toxic", "permission": "view_log", "object_type": "guild_bank" }│
  │                                                                                 │
  │  2. Bulk delete all returned tuples in one call:                               │
  │     DELETE /zanzibar/stores/org_dragonkeep/relationships/bulk [all tuples from step 1] │
  │                                                                                 │
  │  The player's next game action — whether it's trying to access the bank or     │
  │  view officer chat — hits a Zanzibar deny. They see a "You are not a member    │
  │  of IronCrest" message. Their JWT still lets them log into DragonKeep and      │
  │  play the game — they just have zero guild access.                             │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 6: Kira Schedules a Raid — Event-Scoped Access

  Kira schedules the weekly guild raid on the Dragon's Sanctum dungeon:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /raids                                                                   │
  │  Authorization: Bearer eyJ...  (Kira's officer token)                         │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "guild_id":   "guild_ironcrest",
    "dungeon":    "dragons-sanctum",
    "raid_id":    "raid_ds_2026_0225",
    "start_time": "2026-02-25T20:00:00Z",
    "max_slots":  20,
    "strategy_doc_url": "https://strat.ironcrest.gg/ds-strategy"
  }

  Platform writes Zanzibar tuples for the raid:
  { "object": "raid:raid_ds_2026_0225", "relation": "raid_leader", "subject": "user:usr_kira" }

  Guild members (including recruits) can RSVP:
  POST /raids/raid_ds_2026_0225/rsvp  → writes:
  { "object": "raid:raid_ds_2026_0225", "relation": "standby", "subject": "user:usr_ash" }
  { "object": "raid:raid_ds_2026_0225", "relation": "standby", "subject": "user:usr_pixel" }

  Kira reviews signups and confirms 20 slots. Ash gets confirmed; Pixel does not (only
  20 slots available):

  // Ash confirmed:
  {
    "remove": { "object": "raid:raid_ds_2026_0225", "relation": "standby",        "subject": "user:usr_ash" },
    "add":    { "object": "raid:raid_ds_2026_0225", "relation": "confirmed_slot", "subject": "user:usr_ash" }
  }

  Now Ash can view the strategy document. Pixel (standby) cannot:
  Can usr_ash view_strategy of raid:raid_ds_2026_0225?   → confirmed_slot → can_view → YES
  Can usr_pixel view_strategy of raid:raid_ds_2026_0225? → standby → can_view → YES (standby included)
  Can usr_pixel lead raid:raid_ds_2026_0225?             → raid_leader only → NO

  What just happened?
  ─────────────────
  The raid is its own Zanzibar object, independent of the guild. Pixel being a Recruit in
  the guild doesn't stop them from signing up for and viewing the raid strategy — raid access
  is determined by raid tuples, not guild rank. But leading the raid requires a specific
  raid_leader tuple, which Kira wrote for herself (and can delegate to others per raid).

---

## Step 7: VaultRun Open Championship — Tournament Setup

  The VaultRun competitive scene is heating up. Sofia's team (as organizer) creates the
  Season 3 Open Championship:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /tournaments                                                             │
  │  Authorization: Bearer eyJ...  (organizer service account token)              │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "tournament_id":  "trn_vr_open_s3",
    "name":           "VaultRun Open Championship — Season 3",
    "format":         "single_elimination",
    "team_count":     8,
    "prize_pool":     50000,
    "brackets": [
      { "round": "quarterfinals", "matches": [
          { "id": "bracket_qf1", "seeds": [1, 8] },
          { "id": "bracket_qf2", "seeds": [2, 7] },
          { "id": "bracket_qf3", "seeds": [3, 6] },
          { "id": "bracket_qf4", "seeds": [4, 5] }
      ]},
      { "round": "semifinals", "matches": [
          { "id": "bracket_sf1", "winner_of": ["bracket_qf1", "bracket_qf2"] },
          { "id": "bracket_sf2", "winner_of": ["bracket_qf3", "bracket_qf4"] }
      ]},
      { "round": "grand_final", "matches": [
          { "id": "bracket_gf",  "winner_of": ["bracket_sf1", "bracket_sf2"] }
      ]}
    ]
  }

  Tournament organizer tuple:
  { "object": "tournament:trn_vr_open_s3", "relation": "organizer", "subject": "user:usr_sofia" }

  Referee Sarah Park is assigned to officiate:
  { "object": "tournament:trn_vr_open_s3", "relation": "referee", "subject": "user:usr_sarah" }

  NovaBurst (seed 1) and GhostPulse (seed 8) are placed in QF1:
  { "object": "bracket:bracket_qf1", "relation": "participant", "subject": "org:org_novabursteports#esports_player" }
  { "object": "bracket:bracket_qf1", "relation": "participant", "subject": "org:org_ghostpulseeports#esports_player" }
  { "object": "bracket:bracket_qf1", "relation": "referee",     "subject": "user:usr_sarah" }

  What just happened?
  ─────────────────
  Each bracket object is an independent Zanzibar node. A team has participant relation on
  their current bracket, giving them access to that bracket's pre-match lobby, strategy
  tools, and warm-up servers. They have no tuples on other brackets — if NovaBurst somehow
  tried to access the SF1 pre-match lobby before winning QF1, the Zanzibar check fails.

  The organizer relation is on the tournament object. Sofia can access all brackets by
  transitivity (tournament organizer → bracket organizer via the namespace config). Referees
  are placed on specific brackets — Sarah officiates all matches but could be split
  across multiple officials for larger tournaments.

---

## Step 8: Match Goes Live — NovaBurst vs GhostPulse

  QF1 starts. The matchmaking service creates the live match object:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /matches                                                                 │
  │  Authorization: Bearer <matchmaking_api_key>                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "match_id":      "match_qf1_vrs3",
    "bracket_id":    "bracket_qf1",
    "team_a":        "org_novaburstesports",
    "team_b":        "org_ghostpulseesports",
    "scheduled_at":  "2026-02-25T18:00:00Z",
    "spectator_mode":"public"
  }

  Matchmaking writes match Zanzibar tuples:

  // Players can play
  { "object": "match:match_qf1_vrs3", "relation": "participant", "subject": "org:org_novaburstesports#esports_player" }
  { "object": "match:match_qf1_vrs3", "relation": "participant", "subject": "org:org_ghostpulseesports#esports_player" }

  // Referee can officiate
  { "object": "match:match_qf1_vrs3", "relation": "referee",    "subject": "user:usr_sarah" }

  // Public match — anyone can spectate
  { "object": "match:match_qf1_vrs3", "relation": "public",     "subject": "user:*" }

  Spectator access checks for different viewer types:
  Can user:* view_live match:match_qf1_vrs3?        → public → YES (anyone authenticated)
  Can user:* view_live_stats match:match_qf1_vrs3?  → not in vip/participant/ref → NO
  Can usr_riven view_team_comms match:match_qf1_vrs3? → participant → YES
  Can usr_sarah view_team_comms match:match_qf1_vrs3? → referee → YES

  What just happened?
  ─────────────────
  One tuple (public: user:*) opens the spectator stream to all logged-in users. If the match
  were private (invitation tournament, practice scrimmage), that tuple simply wouldn't exist.
  Removing it closes the public stream instantly — no cache to invalidate, no permission to
  revoke per spectator.

  Players can see team comms. Referees can see team comms (for rule enforcement). Regular
  spectators cannot — they watch the gameplay stream but don't hear the team voice channel.

---

## Step 9: Match Session Tokens — Anti-Cheat Integration

  When a match starts, each player needs a short-lived match session token. This token is
  what the anti-cheat system validates on every in-game action:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/session-tokens  (called by matchmaking service when match starts)  │
  │  Authorization: Bearer <matchmaking_api_key>                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "user_id":    "usr_riven",
    "session_type": "match",
    "context": {
      "match_id":  "match_qf1_vrs3",
      "team":      "novaburstesports",
      "role":      "player"
    },
    "permissions": ["game.play"],
    "expires_in":   5400
  }

  Response:
  {
    "session_token": "ses_riven_a7f3...",
    "expires_at":    "2026-02-25T19:30:00Z",
    "match_id":      "match_qf1_vrs3"
  }

  Every game action Riven takes sends this token to the anti-cheat service:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /anticheat/validate-action  (anti-cheat service, internal)              │
  │  Authorization: Bearer <anticheat_api_key>                                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "session_token": "ses_riven_a7f3...",
    "action_type":   "ability_cast",
    "action_data":   { "ability": "flash", "timestamp": 1740505812, "position": [234, 891] },
    "match_id":      "match_qf1_vrs3"
  }

  Anti-cheat validates:
  1. session_token is valid (not expired, not revoked)
  2. session_token.context.match_id == submitted match_id (prevents replaying tokens from other matches)
  3. session_token.permissions includes game.play
  4. Action timestamp is within match window
  5. Action data passes statistical analysis

  Response: { "valid": true } or { "valid": false, "flag": "statistical_anomaly" }

  What just happened?
  ─────────────────
  The session token is:
  - Short-lived (90 minutes — slightly longer than a max match duration)
  - Match-scoped (context.match_id binding prevents cross-match replay attacks)
  - Permission-minimal (game.play only — the match token can't access the player's
    account settings, guild bank, or anything outside the match)

  If Riven disconnects and reconnects mid-match, the matchmaking service issues a new
  session token for the resumed match. The old token can be explicitly revoked, or it
  simply expires — either way, only the current session token is valid.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "A player tries to use a session token from a previous match to    │
  │  manipulate their current match stats."                                        │
  │                                                                                 │
  │  The anti-cheat check at step 2 catches this:                                  │
  │  session_token.context.match_id = "match_qf0_vrs3" (old match)                │
  │  submitted match_id             = "match_qf1_vrs3" (current match)            │
  │  → mismatch → DENY + flag for investigation                                   │
  │                                                                                 │
  │  The session token from the old match is still cryptographically valid (not    │
  │  yet expired) but the context binding rejects it. This is why context binding  │
  │  exists — expiry alone isn't sufficient when tokens can be replayed.          │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 10: NovaBurst Wins — Bracket Advancement

  NovaBurst wins QF1 13-7. GhostPulse is eliminated. Referee Sarah confirms the result:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /brackets/bracket_qf1/advance                                           │
  │  Authorization: Bearer eyJ...  (Sarah's referee token)                        │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "winner_org": "org_novaburstesports", "score": { "nova": 13, "ghost": 7 } }

  This triggers:

  1. Write NovaBurst's participant tuple on SF1:
  { "object": "bracket:bracket_sf1", "relation": "participant",
    "subject": "org:org_novaburstesports#esports_player" }

  2. Revoke all session tokens for match_qf1_vrs3 (match is over)

  3. Mark GhostPulse as eliminated — no SF1 tuple written for them

  NovaBurst can now access the SF1 pre-match lobby:
  Can org:org_novaburstesports#esports_player access_resources bracket:bracket_sf1? → YES
  Can org:org_ghostpulseesports#esports_player access_resources bracket:bracket_sf1? → NO

  GhostPulse players try to grief the SF1 lobby:
  GET /brackets/bracket_sf1/lobby
  Authorization: Bearer eyJ...  (GhostPulse player token)
  → Zanzibar check: no participant tuple → 403 Forbidden

  What just happened?
  ─────────────────
  Access automatically follows advancement. There's no "eliminate" flag to set. Elimination
  is simply the absence of a tuple on the next bracket. The organizer doesn't need to
  configure anything special for eliminated teams — they just don't get the advancement tuple.

  GhostPulse players retain their esports_player role and team org membership. They can still
  watch the tournament as public spectators. They just have no participant relation on any
  remaining brackets. If they re-qualify for a future tournament, they get new bracket tuples.

---

## Step 11: VIP Spectator Access

  The tournament is reaching semifinals. ArenaOS sells VIP spectator passes — access to live
  player stats overlays, damage readouts, and economy graphs that regular spectators don't see.

  A player buys a VIP pass:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /spectator/vip-pass                                                     │
  │  Authorization: Bearer eyJ...  (spectator's player token)                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "tournament_id": "trn_vr_open_s3", "payment_method": "card_****4242" }

  On payment success, the platform writes VIP tuples for all remaining matches:

  { "object": "match:match_sf1_vrs3", "relation": "vip_spectator", "subject": "user:usr_viewer_1" }
  { "object": "match:match_gf_vrs3",  "relation": "vip_spectator", "subject": "user:usr_viewer_1" }

  Now the viewer gets the premium stream:
  Can usr_viewer_1 view_live match:match_sf1_vrs3?       → vip_spectator → view_live → YES
  Can usr_viewer_1 view_live_stats match:match_sf1_vrs3? → vip_spectator → YES
  Can usr_viewer_1 view_team_comms match:match_sf1_vrs3? → vip_spectator NOT in team_comms set → NO

  VIPs see the stats overlay. They still don't hear team voice comms — that's participant and
  referee only, for competitive integrity. The permission boundary is in the namespace definition.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Spectator tier summary:                                                        │
  ├──────────────────┬──────────────┬──────────────┬───────────────────────────────┤
  │  Tier            │ view_live    │ view_stats   │ view_team_comms               │
  ├──────────────────┼──────────────┼──────────────┼───────────────────────────────┤
  │  public (user:*) │     YES      │     NO       │      NO                       │
  ├──────────────────┼──────────────┼──────────────┼───────────────────────────────┤
  │  spectator       │     YES      │     NO       │      NO                       │
  ├──────────────────┼──────────────┼──────────────┼───────────────────────────────┤
  │  vip_spectator   │     YES      │     YES      │      NO                       │
  ├──────────────────┼──────────────┼──────────────┼───────────────────────────────┤
  │  streamer        │     YES      │     YES      │      NO                       │
  ├──────────────────┼──────────────┼──────────────┼───────────────────────────────┤
  │  participant     │     YES      │     YES      │      YES                      │
  ├──────────────────┼──────────────┼──────────────┼───────────────────────────────┤
  │  referee         │     YES      │     YES      │      YES                      │
  └──────────────────┴──────────────┴──────────────┴───────────────────────────────┘

---

## Step 12: Streamer Delegation Token — TwitchCast Broadcast Rights

  TwitchCast is an automated streaming bot that broadcasts the semifinal to 80,000 concurrent
  viewers. It needs VIP-level match access to pull the stats overlay, but it's not a human user
  and shouldn't have a permanent account on ArenaOS.

  Sofia sets up delegation for the semifinal broadcast in two steps:

  Step 1 — Grant delegation scope (Sofia, as platform admin, defines what can be delegated):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /delegation/grant                                                        │
  │  Authorization: Bearer eyJ...  (Sofia's platform token)                       │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "actor_id":         "usr_twitchcast_bot",
    "scope":            ["match.spectate", "match.read.live_stats"],
    "expires_in_hours": 6
  }

  Step 2 — Issue the delegated token (acting as the target service user):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/delegate                                                           │
  │  Authorization: Bearer eyJ...  (Sofia's platform token)                       │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "target_user_id": "usr_twitchcast_bot"
  }

  Response:
  {
    "token":       "dlg_twitch_sf1_a8b3...",
    "expires_at":  "2026-02-25T24:00:00Z",
    "scope":       ["match.spectate", "match.read.live_stats"]
  }

  TwitchCast uses this delegated token to pull the live stats feed:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /matches/match_sf1_vrs3/live-stats                                       │
  │  Authorization: Bearer dlg_twitch_sf1_a8b3...                                 │
  └────────────────────────────────────────────────────────────────────────────────┘

  Server validates:
  1. Token has match.read.live_stats in delegation scope ✓
  2. Delegation grant not expired ✓
  3. Token not expired ✓
  → Returns live stats data for broadcast overlay

  The stream ends. Sofia revokes the delegation grant:
  DELETE /delegation/grant/usr_twitchcast_bot
  → TwitchCast loses all match access immediately

  What just happened?
  ─────────────────
  TwitchCast had broadcast rights for exactly two matches, expiring in 6 hours regardless.
  The delegation grant is scoped to specific permissions (match.spectate, match.read.live_stats)
  and bound to a specific actor (usr_twitchcast_bot). If someone intercepts the delegated token,
  they can only access match spectating data — nothing else. The delegation doesn't grant TwitchCast an account,
  guild access, or anything outside match data. If their systems get breached, the blast
  radius is: live match stats for two semifinal matches, for up to 6 hours.

---

## Step 13: Private Match Spectating — NovaBurst Practice Scrimmage

  Between tournament rounds, NovaBurst runs a private scrimmage against a stand-in team.
  Their coach Petra needs to watch and take notes. No one outside the team should be able
  to see. This is not a public event.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /matches                                                                 │
  │  Authorization: Bearer <matchmaking_api_key>                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "match_id":      "match_nova_scrimmage_001",
    "match_type":    "practice",
    "spectator_mode":"private",
    "team_a":        "org_novaburstesports"
  }

  No public tuple is written. The match exists in the system, but:
  Can user:* view_live match:match_nova_scrimmage_001?
  → no public tuple, no spectator tuple → DENY

  NovaBurst explicitly invites Petra (coach) and their analyst:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /matches/match_nova_scrimmage_001/invite-spectators                     │
  │  Authorization: Bearer eyJ...  (team captain's token)                         │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "invitees": ["usr_petra", "usr_analyst_nova"],
    "access_level": "vip_spectator"
  }

  Tuples written:
  { "object": "match:match_nova_scrimmage_001", "relation": "invited_viewer", "subject": "user:usr_petra" }
  { "object": "match:match_nova_scrimmage_001", "relation": "invited_viewer", "subject": "user:usr_analyst_nova" }

  But wait — the match namespace gives invited_viewer the same view_live access as regular
  spectators. Petra needs stats too (she's coaching). The team captain also adds:
  { "object": "match:match_nova_scrimmage_001", "relation": "vip_spectator", "subject": "user:usr_petra" }

  Now Petra has both invited_viewer and vip_spectator — she can watch AND see stats overlay.

  Somebody on another team tries to find the scrimmage to scout:
  GET /matches/match_nova_scrimmage_001/live-stats
  → Zanzibar check → no spectator, no public, no vip tuple for them → 403

  Even if they know the match ID, the access check stops them.

  What just happened?
  ─────────────────
  Private matches are just matches without a public tuple. No "privacy flag" to configure.
  The default state of a Zanzibar object is deny — nothing can be accessed until a tuple
  grants it. A private match simply never gets the public:user:* tuple.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "A tournament organizer wants to let eliminated teams watch their   │
  │  rivals' quarterfinal replays — but not the live matches, just VODs."          │
  │                                                                                 │
  │  Create a "replay" Zanzibar namespace with a viewer relation.                  │
  │  When a match ends, write:                                                     │
  │  { "object": "replay:match_qf1_vrs3", "relation": "viewer",                   │
  │    "subject": "org:org_ghostpulseesports#esports_player" }                    │
  │                                                                                 │
  │  GhostPulse can view the replay. They had no access to the live match after    │
  │  elimination. Live and replay are separate objects — access to one doesn't     │
  │  imply access to the other.                                                    │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 14: Service API Keys — The Platform Automation Layer

  Four services run the ArenaOS backend. Each gets a scoped API key:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/users/create-service-account  (Sofia's platform token)           │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Matchmaking — creates/closes matches, writes bracket advancement
  {
    "email": "matchmaking-service@svc.arenaos.gg",
    "name": "matchmaking-service",
    "permissions": [
      "tournament.organize",
      "game.play"
    ],
    "org_id": "org_arenaos"
  }

  // Anti-cheat — reads player history, writes violation flags
  {
    "email": "anticheat-service@svc.arenaos.gg",
    "name": "anticheat-service",
    "permissions": [
      "game.read.stats",
      "game.read.replays"
    ],
    "org_id": "org_arenaos"
  }
  // Anti-cheat writes violation flags directly via Zanzibar /relationships endpoint
  // and a separate violations API — not via game.write.* permissions

  // Leaderboard — reads match results, writes rankings
  {
    "email": "leaderboard-service@svc.arenaos.gg",
    "name": "leaderboard-service",
    "permissions": [
      "game.read.stats",
      "tournament.officiate"
    ],
    "org_id": "org_arenaos"
  }

  // Streaming relay — pulls match state for spectators
  {
    "email": "streaming-relay@svc.arenaos.gg",
    "name": "streaming-relay",
    "permissions": [
      "match.spectate",
      "match.read.live_stats"
    ],
    "org_id": "org_arenaos"
  }

  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  Service Key Blast Radius                                                        │
  ├──────────────────────────┬───────────────────────────────────────────────────────┤
  │  Compromised key         │  Worst case                                           │
  ├──────────────────────────┼───────────────────────────────────────────────────────┤
  │  matchmaking-service     │  Creates fake matches or prematurely closes real ones.│
  │                          │  Cannot modify player accounts or guild data.         │
  ├──────────────────────────┼───────────────────────────────────────────────────────┤
  │  anticheat-service       │  Reads player history and replays. Cannot ban players │
  │                          │  directly — that goes through a human review workflow.│
  ├──────────────────────────┼───────────────────────────────────────────────────────┤
  │  leaderboard-service     │  Reads stats, updates rankings. Cannot access player  │
  │                          │  account data, guild data, or live match control.     │
  ├──────────────────────────┼───────────────────────────────────────────────────────┤
  │  streaming-relay         │  Reads live match state. Cannot influence the game,  │
  │                          │  write any data, or access player accounts.           │
  └──────────────────────────┴───────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "We want to let players sell in-game items from their guild bank    │
  │  to a marketplace. The marketplace service needs to read guild bank balances    │
  │  and write withdrawal records."                                                 │
  │                                                                                 │
  │  Create a marketplace-service account with guild.read.bank permission.         │
  │  Withdrawals are a write, but withdrawal RECORDS are a separate concern from   │
  │  the actual bank balance change. The marketplace service gets:                 │
  │  - guild.read.bank: read balances to validate sufficient funds                │
  │  - Zanzibar check: does the requesting player have deposit/withdraw rights?    │
  │    (The marketplace can't bypass the Zanzibar gate — it can only act on        │
  │     behalf of a player who already has the right relations)                   │
  │                                                                                 │
  │  The service API key has no guild bank write access on its own. It reads the   │
  │  balance, confirms the player has withdraw rights via Zanzibar, then the       │
  │  actual withdrawal is executed as the player's action (with the player's token)│
  │  — not as the service's action. Accountability stays with the player.          │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

  Full System Summary
  ──────────────────

  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  Authorization decision map                                                      │
  ├───────────────────────────────────────┬──────────────────────────────────────────┤
  │  Question                             │  How it's answered                       │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can Pixel access guild bank?         │  No bank tuple → Zanzibar DENY           │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can Lyra withdraw from guild bank?   │  deposit_only tuple → withdraw DENY      │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can GhostPulse access SF1 lobby?     │  No SF1 participant tuple → DENY         │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can public spectators hear           │  team_comms requires participant/referee  │
  │  NovaBurst voice comms?               │  → no public relation in that permission │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can TwitchCast access QF1 stats      │  context.match_ids only covers SF1/SF2   │
  │  using the SF broadcast token?        │  → context binding DENY                  │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can a spectator replay a session     │  context.match_id binding → mismatch     │
  │  token from QF1 in SF1?              │  → DENY + anti-cheat flag               │
  ├───────────────────────────────────────┼──────────────────────────────────────────┤
  │  Can NovaBurst watch their own QF1    │  Replay namespace, explicit viewer tuple  │
  │  VOD after the match?                 │  → YES if organizer writes it            │
  └───────────────────────────────────────┴──────────────────────────────────────────┘

  Org layer    → "You are a VaultRun player" / "You are on NovaBurst Esports"
  Zanzibar     → "You are an Officer in IronCrest" / "You are a QF1 participant"
  Session token→ "You are actively playing in match_qf1_vrs3, for the next 90 minutes"
  Delegation   → "TwitchCast may stream SF1 and SF2, until midnight"

---

## Appendix: Complete IronCrest Guild Tuple Set

  ─── FOUNDING ────────────────────────────────────────────────────────────────────
  guild:guild_ironcrest          #guild_leader   user:usr_magnus
  guild_bank:guild_bank_ironcrest #full_access   user:usr_magnus

  ─── OFFICER SETUP ───────────────────────────────────────────────────────────────
  guild:guild_ironcrest          #officer        user:usr_lyra
  guild_bank:guild_bank_ironcrest #deposit_only  user:usr_lyra

  guild:guild_ironcrest          #officer        user:usr_kira
  guild_bank:guild_bank_ironcrest #full_access   user:usr_kira

  ─── MEMBER ONBOARDING ───────────────────────────────────────────────────────────
  guild:guild_ironcrest          #member         user:usr_ash
  guild_bank:guild_bank_ironcrest #view_only     user:usr_ash

  ─── RECRUIT PROBATION ───────────────────────────────────────────────────────────
  guild:guild_ironcrest          #recruit        user:usr_pixel     ← provisional

  ─── PROMOTION ───────────────────────────────────────────────────────────────────
  REMOVED: guild:guild_ironcrest #recruit        user:usr_pixel
  ADDED:   guild:guild_ironcrest #member         user:usr_pixel
  ADDED:   guild_bank:guild_bank_ironcrest #view_only user:usr_pixel

  ─── RAID EVENT ──────────────────────────────────────────────────────────────────
  raid:raid_ds_2026_0225         #raid_leader    user:usr_kira
  raid:raid_ds_2026_0225         #confirmed_slot user:usr_ash
  raid:raid_ds_2026_0225         #standby        user:usr_pixel

## Appendix: Complete NovaBurst Tournament Tuple Progression

  ─── TOURNAMENT REGISTERED ───────────────────────────────────────────────────────
  bracket:bracket_qf1            #participant    org:org_novaburstesports#esports_player
  bracket:bracket_qf1            #participant    org:org_ghostpulseesports#esports_player
  bracket:bracket_qf1            #referee        user:usr_sarah

  ─── MATCH LIVE ──────────────────────────────────────────────────────────────────
  match:match_qf1_vrs3           #participant    org:org_novaburstesports#esports_player
  match:match_qf1_vrs3           #participant    org:org_ghostpulseesports#esports_player
  match:match_qf1_vrs3           #referee        user:usr_sarah
  match:match_qf1_vrs3           #public         user:*

  ─── MATCH ENDS: NOVABURSTS WINS ─────────────────────────────────────────────────
  bracket:bracket_sf1            #participant    org:org_novaburstesports#esports_player
  (no tuple for GhostPulse on sf1 — eliminated)
  (all session tokens for match_qf1_vrs3 revoked)

  ─── SF1 SPECTATING ──────────────────────────────────────────────────────────────
  match:match_sf1_vrs3           #vip_spectator  user:usr_viewer_1  (paid VIP)
  match:match_sf1_vrs3           #streamer       user:dlg_twitch_sf1 (delegation token)
  match:match_sf1_vrs3           #public         user:*

  ─── SCRIMMAGE (PRIVATE) ─────────────────────────────────────────────────────────
  match:match_nova_scrimmage_001 #participant    org:org_novaburstesports#esports_player
  match:match_nova_scrimmage_001 #invited_viewer user:usr_petra
  match:match_nova_scrimmage_001 #vip_spectator  user:usr_petra
  (no public tuple — private match)
