question: We are building "Learnly" — a B2B e-learning platform. Institutions (bootcamps, corporate training teams, universities) buy access and deploy courses for their students.
  We have course content that must only be visible to enrolled students, student cohorts that run the same course at different times but must stay isolated from each other,
  instructors who need to delegate grading to teaching assistants, and guest experts who review final projects for just one cohort. Walk us through the whole thing.

● E-learning is a fascinating auth challenge because access is almost entirely relationship-driven — not role-driven. A student doesn't have a "can view lessons" permission bit.
  They have a Zanzibar enrollment tuple that says "this student is a member of cohort Jan-2026, which has access to these lessons." Take away the tuple and the course
  disappears from their dashboard. Add it back and it reappears. Org roles set the ceiling; Zanzibar tuples define exactly what's inside.

  By the end you'll have:

  - A platform / institution / department org hierarchy
  - Zanzibar schemas for courses, cohorts, lessons, and assignment sets
  - Cohort-gated content: same course, two cohorts, completely isolated
  - Student self-registration and corporate bulk enrollment
  - TA delegation: Sara delegates Module 3 grading to Marco (scoped, not full instructor)
  - Guest expert review: Dr. Watanabe gets time-limited access for final projects only
  - Course completion tuple: Zanzibar fact that unlocks certificates
  - Service API keys for Video CDN, Certificate Service, and Analytics

  ---
  Concept: Why Cohorts Are Not Orgs

  Your first instinct might be: "put each cohort in a child org." This works at a small scale
  but breaks down because:

  - The same instructor teaches both cohorts — they'd need membership in every cohort org
  - Moving a student from one cohort to another requires removing/adding org membership,
    which affects their token and requires a re-login
  - You can't easily query "all students across all Jan-2026 cohorts of all courses"
  - Cohorts are ephemeral (they end) — cleaning up dead child orgs adds operational overhead

  The right model: cohorts are Zanzibar objects, not orgs. A student's org membership
  (institution org) stays constant. Their cohort membership is a Zanzibar tuple. Changing
  cohorts = delete one tuple, write another. No token re-issue, no org change, instant.

  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  What lives in the org layer vs Zanzibar layer                                   │
  ├──────────────────────────────┬───────────────────────────────────────────────────┤
  │  Org layer                   │ Zanzibar layer                                    │
  ├──────────────────────────────┼───────────────────────────────────────────────────┤
  │  Student is enrolled at      │ Student is in cohort Jan-2026                     │
  │  Brightline Academy          │                                                   │
  ├──────────────────────────────┼───────────────────────────────────────────────────┤
  │  Sara is an instructor at    │ Sara is the lead instructor of Python Fundamentals│
  │  Brightline Academy          │                                                   │
  ├──────────────────────────────┼───────────────────────────────────────────────────┤
  │  Marco is a TA at            │ Marco is the grader for jan-2026 module 3         │
  │  Brightline Academy          │                                                   │
  ├──────────────────────────────┼───────────────────────────────────────────────────┤
  │  Student has role "student"  │ Student can view lesson:python-fund-L03 because   │
  │  (sets permission ceiling)   │ they are a member of cohort:jan-2026 which has    │
  │                              │ access to that lesson                             │
  └──────────────────────────────┴───────────────────────────────────────────────────┘

  ---
  Concept: Cohort Isolation Without Negative Rules

  Alex is in the Jan-2026 Python cohort. Emma is in the Mar-2026 cohort. They're taking the
  same course. Isolation requirements:

  - Alex and Emma both see the same lesson content (same videos, same problem sets)
  - Alex sees Jan-2026 peer discussions, Emma sees Mar-2026 peer discussions
  - Alex's submission grades are not visible to Emma and vice versa
  - If Mar-2026 cohort is ahead in the curriculum, their unlock schedule doesn't affect Alex

  None of this requires writing "Emma cannot see Jan-2026 data." You never write negative rules.
  You write: "lesson:python-fund-L03 is accessible to cohort:jan-2026#student." Emma is not
  in cohort:jan-2026, so the Zanzibar check fails. Absence of a tuple is denial.

  ---
  The Architecture: Learnly

  Learnly (platform org — Priya, platform engineering)
  │
  ├── [CHILD ORG] Brightline Academy       (Dr. James Liu — bootcamp, 3 courses)
  │   ├── Members: James (admin), Sara (instructor), Marco (ta), Alex, Emma (students)
  │   └── [CHILD ORG] Data Engineering Dept (optional dept subdivision)
  │
  ├── [CHILD ORG] TechCorp Training        (HR team — corporate e-learning)
  │   └── Members: HR Admin, 20 enrolled employees
  │
  └── [CHILD ORG] OpenCourse Creators      (independent course authors — marketplace model)

  Zanzibar objects (not orgs):
  ├── course:python-fundamentals
  ├── course:data-engineering-101
  ├── cohort:python-jan-2026           (instance: Jan 2026 Python cohort)
  ├── cohort:python-mar-2026           (instance: Mar 2026 Python cohort)
  ├── lesson:python-fund-L01 through L24
  ├── assignment_set:jan-2026-mod3     (Module 3 assignments for Jan cohort)
  └── assignment_set:mar-2026-mod3     (Module 3 assignments for Mar cohort — separate)

  Characters:
  - Priya Sharma        — Learnly founder/CTO (platform owner)
  - Dr. James Liu       — Brightline Academy director (institution admin)
  - Sara Chen           — Lead Python Instructor
  - Marco Reyes         — Teaching Assistant (Python Fundamentals)
  - Alex Torres         — Student, Python Jan-2026 cohort
  - Emma Wilson         — Student, Python Mar-2026 cohort
  - Dr. Kenji Watanabe  — Guest Expert (guest reviews final projects, one cohort only)
  - TechCorp HR         — Corporate admin bulk-enrolling 20 employees

  ---

## Step 1: Platform Setup

  Priya creates the Learnly platform org and defines the permission schema:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/register                                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "priya@learnly.io",
    "password": "...",
    "name": "Priya Sharma",
    "org_name": "Learnly",
    "org_slug": "learnly"
  }

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /permissions/registry/register  (four calls, one per service)           │
  │  Authorization: Bearer eyJ...  (Priya's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "service": "course",
    "description": "Course content, roster, submissions, and grading",
    "actions": ["read", "write"],
    "resources": ["content", "roster", "submissions", "grades", "analytics"]
  }

  {
    "service": "cohort",
    "description": "Cohort lifecycle and visibility",
    "actions": ["manage", "read"],
    "resources": []
  }

  {
    "service": "institution",
    "description": "Institution-level administration",
    "actions": ["manage"],
    "resources": []
  }

  {
    "service": "platform",
    "description": "Platform-wide management and analytics",
    "actions": ["manage", "read"],
    "resources": ["institutions", "analytics"]
  }

  Now create the roles that map to real e-learning job functions:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/roles  (four calls)                                               │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Institution admin — manages their org, courses, roster
  {
    "name": "institution_admin",
    "permissions": [
      "course.read.content", "course.write.content",
      "course.read.roster",  "course.write.roster",
      "course.read.analytics", "cohort.manage", "cohort.read",
      "institution.manage"
    ]
  }

  // Instructor — creates/edits course content, manages their cohorts, sees submissions
  {
    "name": "instructor",
    "permissions": [
      "course.read.content", "course.write.content",
      "course.read.roster",
      "course.read.submissions", "course.write.grades",
      "cohort.read"
    ]
  }

  // Teaching assistant — read-only on content, can grade (scoped by Zanzibar)
  {
    "name": "ta",
    "permissions": [
      "course.read.content",
      "course.read.submissions",
      "course.write.grades",
      "cohort.read"
    ]
  }

  // Student — can view content (gated by Zanzibar enrollment), submit work
  {
    "name": "student",
    "permissions": [
      "course.read.content",
      "cohort.read"
    ]
  }

  What just happened?
  ─────────────────
  Notice that the "student" role has course.read.content — but that's only the permission
  ceiling. A student having course.read.content does NOT mean they can see all courses.
  The Zanzibar layer is the second gate: "which specific content does this student's
  enrollment entitle them to?" The org role says "you're allowed to read course content in
  principle." Zanzibar says "you may read exactly these lessons, because you're enrolled
  in cohort jan-2026 which has access to them."

---

## Step 2: Institution Onboarding — Brightline Academy

  Dr. James Liu signs up for Learnly. Priya's platform creates an institution org:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations                                                           │
  │  Authorization: Bearer eyJ...  (Priya's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "name": "Brightline Academy",
    "slug": "brightline",
    "parent_id": "org_learnly",
    "settings": {
      "max_seats": 200,
      "invitation_only": false,
      "default_role": "student"
    }
  }

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/org_brightline/invite                                     │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "james@brightlineacademy.com",
    "role": "institution_admin"
  }

  James accepts. Now he invites Sara as instructor and Marco as TA:

  {
    "email": "sara@brightlineacademy.com",
    "role": "instructor"
  }

  {
    "email": "marco@brightlineacademy.com",
    "role": "ta"
  }

  What just happened?
  ─────────────────
  Brightline Academy is a child org of Learnly. James has institution_admin role scoped to
  Brightline — he can manage his institution's courses and roster but can't see TechCorp
  Training's data. Sara and Marco are members of the Brightline org with instructor/ta roles.

  Being a TA at the org level means Marco has course.write.grades in principle. But which
  assignments he can grade is determined by Zanzibar tuples set up in Step 8. Without the
  right tuple, the permission is useless — the server checks both.

---

## Step 3: Zanzibar E-Learning Schema

  Before Sara can create a course, the platform needs Zanzibar namespaces that model the
  relationships in a learning environment:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_brightline/namespaces                               │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Course — the evergreen content object (not tied to a specific cohort run)
  {
    "name": "course",
    "relations": {
      "owner":       {},
      "instructor":  {},
      "ta":          {},
      "enrolled":    {},
      "can_edit":    { "union": ["owner", "instructor"] },
      "can_view":    { "union": ["owner", "instructor", "ta", "enrolled"] }
    },
    "permissions": {
      "edit_content":   { "relation": "can_edit" },
      "view_content":   { "relation": "can_view" },
      "view_roster":    { "union": ["owner", "instructor", "ta"] },
      "manage_cohorts": { "union": ["owner", "instructor"] }
    }
  }

  // Cohort — a timed run of a course (Jan 2026 instance of Python Fundamentals)
  {
    "name": "cohort",
    "relations": {
      "lead_instructor": {},
      "ta":              {},
      "student":         {},
      "can_teach":       { "union": ["lead_instructor", "ta"] },
      "can_attend":      { "union": ["lead_instructor", "ta", "student"] }
    },
    "permissions": {
      "manage":     { "relation": "lead_instructor" },
      "teach":      { "relation": "can_teach" },
      "attend":     { "relation": "can_attend" },
      "view_peers": { "relation": "can_attend" }
    }
  }

  // Lesson — an individual content unit within a course
  {
    "name": "lesson",
    "relations": {
      "course_staff":     {},
      "cohort_enrolled":  {},
      "public_preview":   {}
    },
    "permissions": {
      "view": { "union": ["course_staff", "cohort_enrolled", "public_preview"] },
      "edit": { "relation": "course_staff" }
    }
  }

  // Assignment set — the collection of submissions for one module, one cohort
  {
    "name": "assignment_set",
    "relations": {
      "instructor": {},
      "grader":     {},
      "submitter":  {}
    },
    "permissions": {
      "submit":               { "relation": "submitter" },
      "view_own_submission":  { "relation": "submitter" },
      "view_all_submissions": { "union": ["instructor", "grader"] },
      "write_grade":          { "union": ["instructor", "grader"] }
    }
  }

  // Completion record — written when a student finishes a course
  {
    "name": "completion",
    "relations": {
      "earner":    {},
      "verifier":  {}
    },
    "permissions": {
      "claim_certificate": { "relation": "earner" },
      "verify":            { "union": ["earner", "verifier"] }
    }
  }

  What just happened?
  ─────────────────
  Five namespaces define how every access decision in the platform works:

  course       → evergreen content and its instructional staff
  cohort       → a live run with enrolled students and timing
  lesson       → individual content gated by cohort membership (the key piece)
  assignment_set → grading scope, where TA delegation happens
  completion   → the Zanzibar fact that a student earned a certificate

  The "lesson" namespace is the most important. Notice cohort_enrolled is a relation — not
  a user ID. In practice it holds a userset reference: "cohort:python-jan-2026#student."
  Every student in that cohort can view the lesson, without writing a tuple per student.
  Enroll 100 students? One cohort#student tuple is added. All 100 get lesson access instantly.

---

## Step 4: Sara Creates the Python Fundamentals Course

  Sara logs in to Learnly's course builder and creates the course:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /courses                                                                 │
  │  Authorization: Bearer eyJ...  (Sara's instructor token)                      │
  │  X-Org-Id: org_brightline                                                     │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "title":       "Python Fundamentals",
    "slug":        "python-fund",
    "description": "12-week bootcamp: Python from zero to job-ready",
    "org_id":      "org_brightline",
    "modules": [
      { "id": "mod1", "title": "Variables & Control Flow",  "lessons": 4 },
      { "id": "mod2", "title": "Functions & Data Structures", "lessons": 5 },
      { "id": "mod3", "title": "OOP & Design Patterns",    "lessons": 6 },
      { "id": "mod4", "title": "Final Projects",           "lessons": 3 }
    ]
  }

  Response: { "course_id": "crs_python_fund", ... }

  The platform writes the Zanzibar course ownership tuple:

  [
    {
      "object":   "course:crs_python_fund",
      "relation": "instructor",
      "subject":  "user:usr_sara"
    },
    {
      "object":   "course:crs_python_fund",
      "relation": "owner",
      "subject":  "org:org_brightline#institution_admin"
    }
  ]

  Sara creates individual lessons. Each starts as a draft — only visible to course staff:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /courses/crs_python_fund/lessons                                        │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "title":  "What is Python?",
    "lesson_id": "lesson_pf_L01",
    "status": "draft",
    "content_url": "https://cdn.learnly.io/crs_python_fund/L01.mp4"
  }

  Draft lesson → Zanzibar: only course_staff can view
  {
    "object":   "lesson:lesson_pf_L01",
    "relation": "course_staff",
    "subject":  "course:crs_python_fund#can_edit"
  }

  When Sara publishes a lesson, the platform adds the cohort access:
  POST /lessons/lesson_pf_L01/publish

  The publish endpoint writes:
  {
    "object":   "lesson:lesson_pf_L01",
    "relation": "cohort_enrolled",
    "subject":  "cohort:cohort_jan_2026#student"
  }
  {
    "object":   "lesson:lesson_pf_L01",
    "relation": "cohort_enrolled",
    "subject":  "cohort:cohort_mar_2026#student"
  }

  What just happened?
  ─────────────────
  Two separate tuples cover two cohorts. Both cohorts get the same lesson content. But
  the cohort's discussions, submissions, and peer interactions are separate objects —
  so students in different cohorts never see each other's work even though they watch
  the same video.

  Sara can also create preview lessons (free, no enrollment required):

  {
    "object":   "lesson:lesson_pf_L01",
    "relation": "public_preview",
    "subject":  "user:*"
  }

  user:* is the wildcard subject — anyone authenticated can view this lesson, even if
  they're not enrolled. This is how free-preview/trailer lessons work.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Lesson visibility summary:                                                     │
  │                                                                                 │
  │  Status: draft   → only course_staff (Sara, James) can view                   │
  │  Status: published → cohort:jan-2026#student + cohort:mar-2026#student        │
  │  Status: preview  → user:* (anyone authenticated)                             │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 5: Creating the Jan-2026 Cohort

  Sara creates the Jan 2026 run of Python Fundamentals:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /cohorts                                                                 │
  │  Authorization: Bearer eyJ...  (Sara's token)                                 │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "course_id":    "crs_python_fund",
    "cohort_id":    "cohort_jan_2026",
    "name":         "Python Fundamentals — January 2026",
    "start_date":   "2026-01-12",
    "end_date":     "2026-04-06",
    "max_students": 30,
    "org_id":       "org_brightline"
  }

  The platform creates the Zanzibar cohort tuples:

  [
    {
      "object":   "cohort:cohort_jan_2026",
      "relation": "lead_instructor",
      "subject":  "user:usr_sara"
    },
    {
      "object":   "cohort:cohort_jan_2026",
      "relation": "ta",
      "subject":  "user:usr_marco"
    }
  ]

  Sara also creates the Mar-2026 cohort the same way (cohort_mar_2026). She's the lead
  instructor of both — one tuple per cohort, no special configuration needed.

  What just happened?
  ─────────────────
  Sara now has lead_instructor relation on both cohorts. This means:

  Zanzibar check: Can usr_sara manage cohort:cohort_jan_2026?  → YES (lead_instructor)
  Zanzibar check: Can usr_sara manage cohort:cohort_mar_2026?  → YES (lead_instructor)
  Zanzibar check: Can usr_marco manage cohort:cohort_jan_2026? → NO (ta, not lead_instructor)
  Zanzibar check: Can usr_marco teach cohort:cohort_jan_2026?  → YES (ta → can_teach)

  Marco can teach (post announcements, run sessions) but cannot manage (change start date,
  add/remove students, close the cohort). The permission split is in the namespace definition,
  not in application code.

---

## Step 6: Student Self-Registration and Enrollment

  Alex discovers Learnly and registers for Brightline Academy:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/brightline/auth/register                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email":    "alex@email.com",
    "password": "...",
    "name":     "Alex Rivera"
  }

  Response:
  {
    "user":  { "id": "usr_alex", "email": "alex@email.com" },
    "org":   { "id": "org_brightline", "slug": "brightline" },
    "role":  "student",
    "token": "eyJ..."
  }

  Alex is a Brightline member with role "student." His JWT contains:
  {
    "sub":         "usr_alex",
    "org_id":      "org_brightline",
    "role":        "student",
    "permissions": ["course.read.content", "cohort.read"]
  }

  Alex's dashboard is empty. He has the right permissions in principle but no Zanzibar
  enrollment tuples. He can't see any lessons or cohorts yet.

  James enrolls Alex in the January 2026 cohort:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /cohorts/cohort_jan_2026/enroll                                         │
  │  Authorization: Bearer eyJ...  (James's institution_admin token)              │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "user_id": "usr_alex" }

  This writes the Zanzibar enrollment tuple:

  {
    "object":   "cohort:cohort_jan_2026",
    "relation": "student",
    "subject":  "user:usr_alex"
  }

  Alex's dashboard instantly shows all published Python Fundamentals lessons.

  How? Zanzibar expands:
  lesson:lesson_pf_L03 #cohort_enrolled cohort:cohort_jan_2026#student
                                                       ↓
                       user:usr_alex is in cohort:cohort_jan_2026 as student → ALLOW

  Alex never needs a new token. The Zanzibar check happens at request time. His JWT doesn't
  change — the relationship changed.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "What if a student drops out mid-course?"                          │
  │                                                                                 │
  │  DELETE /zanzibar/stores/org_brightline/relationships                            │
  │  {                                                                              │
  │    "object":   "cohort:cohort_jan_2026",                                        │
  │    "relation": "student",                                                       │
  │    "subject":  "user:usr_alex"                                                  │
  │  }                                                                              │
  │                                                                                 │
  │  All lesson access disappears immediately. No token refresh, no cache to bust. │
  │  The Zanzibar check now fails for every lesson:lesson_pf_* check.              │
  │  Alex's org membership (Brightline student role) is unchanged — he can still   │
  │  log in and see his dashboard, it's just empty until re-enrolled.              │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 7: Cohort Isolation — Alex and Emma Never Mix

  Emma registers and enrolls in the Mar-2026 cohort (same process, different cohort_id).
  The enrollment tuple for Emma goes to cohort_mar_2026.

  Now let's verify the isolation:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  Lesson access (same video, both cohorts):                                    │
  │                                                                                │
  │  Can usr_alex view lesson:lesson_pf_L03?                                      │
  │  → cohort_enrolled = cohort:cohort_jan_2026#student                           │
  │  → is usr_alex in cohort_jan_2026 as student? YES → ALLOW                    │
  │                                                                                │
  │  Can usr_emma view lesson:lesson_pf_L03?                                      │
  │  → cohort_enrolled = cohort:cohort_jan_2026#student                           │
  │                     + cohort:cohort_mar_2026#student (both published to)      │
  │  → is usr_emma in cohort_mar_2026 as student? YES → ALLOW                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  They both see the same lesson. Now assignment sets — these are cohort-specific objects:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  Assignment access (cohort-specific):                                         │
  │                                                                                │
  │  Can usr_alex submit to assignment_set:jan_2026_mod3?                         │
  │  → submitter = cohort:cohort_jan_2026#student                                 │
  │  → is usr_alex in cohort_jan_2026? YES → ALLOW                               │
  │                                                                                │
  │  Can usr_emma submit to assignment_set:jan_2026_mod3?                         │
  │  → submitter = cohort:cohort_jan_2026#student                                 │
  │  → is usr_emma in cohort_jan_2026? NO (she's in mar_2026) → DENY             │
  └────────────────────────────────────────────────────────────────────────────────┘

  Emma submits to assignment_set:mar_2026_mod3 — her cohort's equivalent.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  Peer discussion isolation:                                                   │
  │                                                                                │
  │  Forum threads are scoped to a cohort object:                                 │
  │  forum_thread:jan_2026_mod3_q1 #can_view cohort:cohort_jan_2026#student      │
  │                                                                                │
  │  Emma cannot see Jan-2026 forum threads — no tuple connects her cohort        │
  │  to those thread objects. She has her own forum threads in mar-2026.          │
  └────────────────────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  Grade visibility:                                                            │
  │                                                                                │
  │  Can usr_alex view his own submission on assignment_set:jan_2026_mod3?        │
  │  → view_own_submission requires submitter relation → YES                     │
  │                                                                                │
  │  Can usr_alex view all submissions on assignment_set:jan_2026_mod3?           │
  │  → view_all_submissions requires instructor or grader → NO                  │
  │  (Alex is a submitter, not an instructor or grader)                          │
  └────────────────────────────────────────────────────────────────────────────────┘

  What just happened?
  ─────────────────
  The entire isolation story is encoded in which Zanzibar objects got which tuples.
  No application code checks "is this user in the jan-2026 cohort?" — the Zanzibar
  check IS the enforcement. The application just calls check() and renders accordingly.

  This also means the data model is clean: jan-2026 assignment submissions are in one
  assignment_set object; mar-2026 submissions are in another. You never need to filter
  by cohort_id in SQL — the Zanzibar gate stops the request before it reaches the DB.

---

## Step 8: TA Delegation — Sara Delegates Module 3 Grading to Marco

  It's week 7. Module 3 (OOP & Design Patterns) submissions come in. Sara has 28 students
  in the Jan-2026 cohort, each with a 500-line OOP project to grade. She delegates Module 3
  grading to Marco, her teaching assistant.

  Marco already has the "ta" role at the org level (course.write.grades permission). But
  which assignment sets he can grade is controlled by Zanzibar — without a grader tuple,
  his course.write.grades permission hits the Zanzibar gate and is denied.

  Sara adds Marco as grader for the Jan-2026 Module 3 assignment set:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_brightline/relationships                             │
  │  Authorization: Bearer eyJ...  (Sara's instructor token)                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  [
    {
      "object":   "assignment_set:jan_2026_mod3",
      "relation": "grader",
      "subject":  "user:usr_marco"
    }
  ]

  Now Marco can grade Module 3 for the Jan-2026 cohort. Let's verify:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_brightline/check                                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  Can usr_marco write_grade to assignment_set:jan_2026_mod3?
  → write_grade requires instructor OR grader
  → usr_marco has grader relation → YES

  Can usr_marco write_grade to assignment_set:jan_2026_mod4?
  → no grader tuple for Marco on that set
  → usr_marco is not instructor → NO

  Can usr_marco write_grade to assignment_set:mar_2026_mod3?
  → no grader tuple for Marco on Emma's cohort's assignment set
  → NO

  Marco opens the grading dashboard for Module 3. He sees 28 submissions (view_all_submissions
  via grader relation). He grades Alex's submission:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /assignments/jan_2026_mod3/submissions/sub_alex_mod3/grade              │
  │  Authorization: Bearer eyJ...  (Marco's ta token)                            │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "score":    87,
    "feedback": "Clean class hierarchy. Consider adding __repr__ to improve debuggability."
  }

  Server validation chain:
  1. Marco's JWT has course.write.grades (ta role) ✓
  2. Zanzibar check: can usr_marco write_grade on assignment_set:jan_2026_mod3? ✓
  3. Phase 2: assignment_set's org_id = org_brightline = Marco's org_id ✓
  → Grade written.

  What just happened?
  ─────────────────
  Three things work together:
  - Marco's role (ta) gives him the capability to grade — in principle
  - Zanzibar tuple (grader on jan_2026_mod3) makes that capability real for this set
  - Phase 2 org check ensures Marco can't somehow grade submissions in TechCorp Training

  When Module 3 grading is complete, Sara can revoke the delegation:

  DELETE /zanzibar/stores/org_brightline/relationships
  {
    "object":   "assignment_set:jan_2026_mod3",
    "relation": "grader",
    "subject":  "user:usr_marco"
  }

  Marco's dashboard is now empty. His ta role is unchanged — he still has the permission
  in theory. But without the Zanzibar grader tuple, there's nothing to grade.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  TA delegation scope table:                                                     │
  ├────────────────────────────────────┬─────────────────────────────────────────── ┤
  │  Action                            │ Marco allowed?                             │
  ├────────────────────────────────────┼────────────────────────────────────────────┤
  │  Grade jan-2026 Module 3           │ YES (grader tuple on jan_2026_mod3)        │
  ├────────────────────────────────────┼────────────────────────────────────────────┤
  │  Grade jan-2026 Module 4           │ NO (no tuple on jan_2026_mod4)             │
  ├────────────────────────────────────┼────────────────────────────────────────────┤
  │  Grade mar-2026 Module 3           │ NO (separate assignment_set object)        │
  ├────────────────────────────────────┼────────────────────────────────────────────┤
  │  Edit lesson content               │ NO (ta role has no course.write.content)   │
  ├────────────────────────────────────┼────────────────────────────────────────────┤
  │  Add/remove students from cohort   │ NO (ta role has no course.write.roster)    │
  ├────────────────────────────────────┼────────────────────────────────────────────┤
  │  View all Module 3 submissions     │ YES (view_all_submissions via grader)      │
  └────────────────────────────────────┴────────────────────────────────────────────┘

---

## Step 9: Guest Expert Delegation — Dr. Watanabe Reviews Final Projects

  Module 4 is the final project module. Sara invites Dr. Kenji Watanabe — an industry
  expert — to review the final projects and give feedback. Dr. Watanabe is not a Brightline
  employee. He shouldn't have an org membership. His access should expire when the review
  window closes.

  For time-limited external access, the best pattern is Zanzibar relationships with
  `expires_at` — the relationship auto-expires and no cleanup is needed. For the delegation
  flow itself, the auth service uses a two-step grant-then-delegate process.

  Step 1 — Sara creates a delegation grant (defines what can be delegated):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /delegation/grant                                                       │
  │  Authorization: Bearer eyJ...  (Sara's instructor token)                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "actor_id":         "usr_sara",
    "scope":            ["course.read.submissions", "course.write.grades", "course.read.content"],
    "expires_in_hours": 336
  }

  Response:
  {
    "grant_id":   "grnt_f8a3...",
    "actor_id":   "usr_sara",
    "scope":      ["course.read.submissions", "course.write.grades", "course.read.content"],
    "expires_at": "2026-04-06T23:59:00Z"
  }

  Step 2 — Sara delegates to Dr. Watanabe (activates the grant for a target user):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/delegate                                                          │
  │  Authorization: Bearer eyJ...  (Sara's instructor token)                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "target_user_id": "usr_kenji"
  }

  Response:
  {
    "delegation_token": "dlg_kenji_f8a3...",
    "expires_at":       "2026-04-06T23:59:00Z"
  }

  Sara also writes a Zanzibar relationship with `expires_at` to scope Dr. Watanabe's
  access to the final project assignment set:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_brightline/relationships                           │
  │  Authorization: Bearer eyJ...  (Sara's instructor token)                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "object":     "assignment_set:jan_2026_mod4_final",
    "relation":   "grader",
    "subject":    "user:usr_kenji",
    "expires_at": "2026-04-06T23:59:00Z"
  }

  Dr. Watanabe uses the delegation token to access the review interface. He sees the
  Python Fundamentals final projects, writes feedback — and after April 6, both the
  delegation token and the Zanzibar relationship expire automatically.

  If Dr. Watanabe tries to access lesson content outside his scope:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /courses/crs_python_fund/modules/mod3/submissions                        │
  │  Authorization: Bearer dlg_kenji_f8a3...                                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response: 403 Forbidden
  {
    "detail": "Delegation scope does not include this resource"
  }

  The scope binding blocks Module 3. He can't drift outside his intended scope.

  What just happened?
  ─────────────────
  Guest experts, external reviewers, and industry mentors are a common pattern in education.
  They need real access (read submissions, write feedback) but should not:
  - Have permanent org membership
  - See the full institution (all courses, all cohorts, all students)
  - Retain access after their engagement ends

  The two-step delegation flow handles this. Sara, as an instructor, creates a grant
  (Step 1) that defines the permission ceiling, then delegates to Dr. Watanabe (Step 2).
  The Zanzibar relationship with `expires_at` scopes exactly which assignment set he can
  access — and it auto-expires, requiring no cleanup. The authority flows from Sara's
  instructor role — she can grant up to what she has (course.read.submissions +
  course.write.grades) and no more.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "What if Sara accidentally issues too many permissions?"           │
  │                                                                                 │
  │  The auth server enforces a delegation ceiling: Sara cannot delegate more than │
  │  her own permissions. If Sara tried to include institution.manage in the       │
  │  delegation grant, the server would reject it with:                            │
  │  { "detail": "Cannot delegate permissions you do not hold" }                  │
  │                                                                                 │
  │  Sara has course.* but not institution.manage. The ceiling is hard-enforced    │
  │  at grant creation time, not just at verification time.                        │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 10: Course Completion and Certificates

  Alex completes all 4 modules, all assignments graded. The platform calculates his final
  grade and marks him as complete. This writes a Zanzibar completion tuple:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_brightline/relationships  (internal, completion svc) │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "object":   "completion:crs_python_fund_usr_alex",
    "relation": "earner",
    "subject":  "user:usr_alex"
  }

  Alex opens his profile and clicks "Download Certificate":

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /certificates/generate                                                   │
  │  Authorization: Bearer eyJ...  (Alex's student token)                         │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "course_id":  "crs_python_fund",
    "cohort_id":  "cohort_jan_2026"
  }

  Server Zanzibar check:
  Can usr_alex claim_certificate on completion:crs_python_fund_usr_alex?
  → earner relation → YES

  Response:
  {
    "certificate_url": "https://certs.learnly.io/cert_alex_python_fund_jan2026.pdf",
    "verification_id": "LEARNLY-2026-A7X9Q",
    "issued_at":       "2026-04-07T10:14:00Z"
  }

  External parties (employers, recruiters) can verify the certificate:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /certificates/verify/LEARNLY-2026-A7X9Q                                  │
  │  (public endpoint — no auth required)                                         │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response:
  {
    "valid":       true,
    "earner":      "Alex Torres",
    "course":      "Python Fundamentals",
    "institution": "Brightline Academy",
    "cohort":      "January 2026",
    "issued_at":   "2026-04-07T10:14:00Z"
  }

  What just happened?
  ─────────────────
  The completion record is a Zanzibar object. It can only be created by the platform's
  completion service (a service API key) — not by students or instructors. The earner
  tuple is the credential.

  If Alex somehow tries to claim a certificate before completing:
  Can usr_alex claim_certificate on completion:crs_python_fund_usr_alex?
  → no earner tuple (completion service hasn't written it) → DENY

  You can't fake completion by knowing the certificate URL pattern. The Zanzibar check
  is authoritative. The certificate is not a signed JWT or database entry that can be
  forged — it's gated by a Zanzibar fact that only the platform's automated grading
  system can write.

---

## Step 11: Corporate Bulk Enrollment — TechCorp Training

  TechCorp buys 20 seats for their engineering team. They want all 20 employees enrolled
  in Python Fundamentals. Their HR Admin handles enrollment programmatically:

  First, TechCorp gets their own institution org (same as Brightline, Step 2). Then their
  HR Admin service account handles bulk enrollment:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/users/create-service-account                                      │
  │  Authorization: Bearer eyJ...  (TechCorp HR Admin token)                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "techcorp-hr-enrollment@svc.learnly.internal",
    "name": "techcorp-hr-enrollment",
    "permissions": ["course.write.roster", "cohort.read"],
    "org_id": "org_techcorp"
  }

  Response: { "id": "...", "email": "...", "api_key": "sk_svc_hr_9f2b...", "name": "..." }

  HR Admin's HRIS system calls Learnly's bulk enrollment API:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /cohorts/cohort_jan_2026/enroll/bulk                                    │
  │  Authorization: Bearer sk_svc_hr_9f2b...                                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "users": [
      { "email": "alice@techcorp.com", "create_if_missing": true },
      { "email": "bob@techcorp.com",   "create_if_missing": true },
      ...20 employees...
    ],
    "role": "student",
    "send_welcome_email": true
  }

  Response:
  {
    "enrolled":    20,
    "created":     18,
    "already_had_accounts": 2,
    "cohort_id":   "cohort_jan_2026"
  }

  The platform:
  1. Creates accounts for 18 employees (invited, set password on first login)
  2. Adds all 20 to org_techcorp with role "student"
  3. Writes 20 Zanzibar enrollment tuples: cohort:cohort_jan_2026 #student user:alice, user:bob, ...

  What just happened?
  ─────────────────
  TechCorp's HRIS system enrolled 20 people without anyone logging into Learnly's UI.
  The service API key has course.write.roster — it can manage enrollment but nothing else.
  It cannot read lesson content, grade submissions, or see other institutions' data.

  TechCorp's employees are in org_techcorp (their institution org), completely separated
  from Brightline Academy's students. Zanzibar enrollment tuples are the only connection
  between TechCorp employees and the cohort. If TechCorp's contract ends:

  DELETE /cohorts/cohort_jan_2026/enroll/bulk  { "org_id": "org_techcorp" }
  → Removes all 20 Zanzibar enrollment tuples atomically
  → All 20 employees lose course access immediately
  → Their accounts still exist (they can log in) but their dashboard is empty

---

## Step 12: Service API Keys — Platform Automation

  Three automated services power Learnly's backend. Each gets a scoped API key:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/users/create-service-account  (three calls, Priya's token)       │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Video CDN — streams lesson content, needs to know if a student is enrolled
  {
    "email": "video-cdn-service@svc.learnly.internal",
    "name": "video-cdn-service",
    "permissions": ["course.read.content"],
    "org_id": "org_learnly"
  }

  // Certificate Service — issues certificates when grading is complete
  {
    "email": "certificate-service@svc.learnly.internal",
    "name": "certificate-service",
    "permissions": ["course.read.submissions", "course.read.analytics"],
    "org_id": "org_learnly"
  }
  // Note: writes completion Zanzibar tuples directly (via /zanzibar/stores/{store_id}/relationships endpoint)

  // Analytics Service — aggregates learning data for institution dashboards
  {
    "email": "analytics-service@svc.learnly.internal",
    "name": "analytics-service",
    "permissions": ["course.read.analytics", "platform.read.analytics"],
    "org_id": "org_learnly"
  }

  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  Service Account Blast Radius                                                    │
  ├─────────────────────────┬────────────────────────────────────────────────────────┤
  │  Compromised key        │ Worst case                                             │
  ├─────────────────────────┼────────────────────────────────────────────────────────┤
  │  video-cdn-service      │ Reads lesson metadata. Cannot grade, enroll, or        │
  │                         │ create completions.                                    │
  ├─────────────────────────┼────────────────────────────────────────────────────────┤
  │  certificate-service    │ Reads submissions and analytics. Cannot write anything │
  │                         │ to course content or enrollment. The Zanzibar write    │
  │                         │ for completion is still gated by Zanzibar check.       │
  ├─────────────────────────┼────────────────────────────────────────────────────────┤
  │  analytics-service      │ Reads anonymized aggregate data. Cannot see individual │
  │                         │ submissions, cannot enroll users, cannot grade.        │
  └─────────────────────────┴────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "The video player needs to verify the student is enrolled before   │
  │  streaming, but the check happens on the CDN edge, not our main server."       │
  │                                                                                 │
  │  The CDN calls the auth service's Zanzibar check endpoint using its API key:   │
  │                                                                                 │
  │  POST /zanzibar/stores/org_brightline/check                                      │
  │  Authorization: Bearer <video_cdn_api_key>                                     │
  │  {                                                                              │
  │    "object":   "lesson:lesson_pf_L08",                                         │
  │    "permission": "view",                                                        │
  │    "subject":  "user:usr_alex"                                                  │
  │  }                                                                              │
  │                                                                                 │
  │  Response: { "allowed": true }                                                  │
  │                                                                                 │
  │  The CDN gets a yes/no without knowing anything about Alex's org, role, or     │
  │  cohort membership. It just checks the one thing it needs to know.             │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 13: Cohort Lifecycle — End of Jan-2026 Cohort

  The Jan-2026 cohort ends on April 6. James runs end-of-cohort cleanup:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /cohorts/cohort_jan_2026/close                                          │
  │  Authorization: Bearer eyJ...  (James's institution_admin token)              │
  └────────────────────────────────────────────────────────────────────────────────┘

  { "archive": true, "retain_completions": true }

  This does:
  1. Sets cohort status to "archived" — no new submissions accepted
  2. Removes all student enrollment tuples (cohort:cohort_jan_2026 #student user:*)
  3. Retains completion tuples (completion:* #earner user:*) — certificates stay valid
  4. Removes Sara and Marco's cohort tuples (cohort_jan_2026 #lead_instructor, #ta)

  After closure:
  Can usr_alex view lesson:lesson_pf_L08?      → NO (enrollment tuple removed)
  Can usr_alex claim_certificate?              → YES (completion tuple retained)
  Can usr_sara manage cohort:cohort_jan_2026?  → NO (lead_instructor tuple removed)

  Alex's certificate is permanent. His course access is not.

  What just happened?
  ─────────────────
  The end-of-cohort cleanup is a precise Zanzibar operation: delete some tuples (enrollment,
  instructor assignment), keep others (completion). There's no "archive org" or "suspend users"
  — just tuple management. The cohort object still exists for audit history; the relationships
  that granted operational access are gone.

  This is also why cohorts are Zanzibar objects, not orgs. Deleting an org cascades through
  auth and could cause unexpected side effects. Removing Zanzibar tuples is scalpel-precise:
  exactly the access you defined is removed, nothing more.

---

  Full System Summary
  ──────────────────

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Access Decision Map                                                            │
  ├─────────────────────────────────┬───────────────────────────────────────────────┤
  │  Question                       │ Answer                                        │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can Alex view lesson L08?      │ org role (student) + Zanzibar (cohort_enrolled │
  │                                 │ via cohort:jan-2026#student)                  │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can Emma see Alex's grade?     │ No — different cohort, different assignment    │
  │                                 │ set, no Zanzibar tuple                         │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can Marco grade Mod 4?         │ No — TA role present, but no grader tuple on  │
  │                                 │ jan_2026_mod4 assignment set                  │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can Dr. Watanabe grade Mod 3?  │ No — delegation token context binds to Mod 4  │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can TechCorp employees see     │ No — they're in org_techcorp, separate from   │
  │  Brightline students' grades?   │ org_brightline, no cross-org tuples           │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can Alex claim certificate     │ Only after completion service writes the       │
  │  before finishing?              │ completion:* #earner tuple — not before        │
  └─────────────────────────────────┴───────────────────────────────────────────────┘

  Org layer  → "You are a student at Brightline Academy"
  Zanzibar   → "You are in cohort jan-2026, which grants lesson access and submission rights"
  Delegation → "You (TA / guest expert) may grade this specific assignment set, until revoked"
  Completion → "You earned this certificate" — a permanent Zanzibar fact, independent of enrollment

---

## Appendix: Complete Zanzibar Tuple Set for Alex's Journey

  ─── REGISTRATION ────────────────────────────────────────────────────────────────
  (org membership: usr_alex → org_brightline, role=student)

  ─── ENROLLMENT ──────────────────────────────────────────────────────────────────
  cohort:cohort_jan_2026  #student           user:usr_alex

  ─── LESSON ACCESS (via cohort userset, not per-student) ─────────────────────────
  lesson:lesson_pf_L01   #cohort_enrolled   cohort:cohort_jan_2026#student
  lesson:lesson_pf_L02   #cohort_enrolled   cohort:cohort_jan_2026#student
  ...
  lesson:lesson_pf_L24   #cohort_enrolled   cohort:cohort_jan_2026#student
  (24 tuples cover all 30 students — not 24×30=720 individual tuples)

  ─── ASSIGNMENT SETS ─────────────────────────────────────────────────────────────
  assignment_set:jan_2026_mod3  #submitter   cohort:cohort_jan_2026#student
  assignment_set:jan_2026_mod3  #instructor  user:usr_sara
  assignment_set:jan_2026_mod3  #grader      user:usr_marco    ← added by Sara, Step 8
  assignment_set:jan_2026_mod4  #submitter   cohort:cohort_jan_2026#student
  assignment_set:jan_2026_mod4  #instructor  user:usr_sara

  ─── GUEST EXPERT (delegation grant + Zanzibar relationship with expires_at) ─────
  delegation grant grnt_f8a3: scope=[course.read.submissions, course.write.grades]
                              delegated to usr_kenji via POST /auth/delegate
                              expires: 2026-04-06
  assignment_set:jan_2026_mod4_final  #grader  user:usr_kenji  expires_at=2026-04-06

  ─── COMPLETION ──────────────────────────────────────────────────────────────────
  completion:crs_python_fund_usr_alex  #earner   user:usr_alex   ← written by cert service

  ─── END OF COHORT CLEANUP ───────────────────────────────────────────────────────
  REMOVED: cohort:cohort_jan_2026 #student user:usr_alex
  REMOVED: cohort:cohort_jan_2026 #lead_instructor user:usr_sara
  REMOVED: cohort:cohort_jan_2026 #ta user:usr_marco
  REMOVED: assignment_set:jan_2026_mod3 #grader user:usr_marco
  EXPIRED: delegation grant grnt_f8a3 + Zanzibar grader tuple on jan_2026_mod4_final (auto-expired)
  KEPT:    completion:crs_python_fund_usr_alex #earner user:usr_alex  ← certificate permanent
