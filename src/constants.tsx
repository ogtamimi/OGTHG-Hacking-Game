
import { Challenge, ChallengeCategory, Difficulty } from './types';

export const INITIAL_CHALLENGES: Challenge[] = [
  {
    id: '1',
    title: 'The Hidden Trail',
    category: ChallengeCategory.WEB,
    difficulty: Difficulty.EASY,
    points: 100,
    description: 'Web developers often leave comments in the HTML code. Can you find the secret flag hidden in the source? All flags in OGTHG follow the format OGT{flag_content}.',
    hint: 'Right-click and "View Page Source" is your best friend. Look for OGT{...}',
    solutionSteps: [
      'Navigate to the target website.',
      'Right-click and select View Page Source.',
      'Search for keywords like "flag" or "OGT{".'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://hidden-comments.local',
    correctPayload: 'OGT{h1dd3n_1n_pl41n_s1ght}',
    flag: 'OGT{h1dd3n_1n_pl41n_s1ght}'
  },
  {
    id: '2',
    title: 'Robot Inspection',
    category: ChallengeCategory.WEB,
    difficulty: Difficulty.EASY,
    points: 100,
    description: 'Search engines are told where not to go using a specific file. Find that file and see what it is hiding. Remember, look for the OGT{} format.',
    hint: 'Look for /robots.txt',
    solutionSteps: [
      'Go to the root of the website.',
      'Append /robots.txt to the URL.',
      'Find the disallowed path that contains the flag.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://crawler-bait.local',
    correctPayload: '/secret-admin-panel/flag.txt',
    flag: 'OGT{r0b0ts_4r3_n0t_s3cur1ty}'
  },
  {
    id: '3',
    title: 'Bypassing the Gate',
    category: ChallengeCategory.SQL,
    difficulty: Difficulty.EASY,
    points: 150,
    description: 'A login form is vulnerable to simple SQL injection. Can you log in without a password and retrieve the OGT flag?',
    hint: "Try the classic ' OR 1=1 --",
    solutionSteps: [
      'Enter any username.',
      "In the password field, enter ' OR 1=1 --.",
      'Submit the form to bypass authentication.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://secure-login.local',
    correctPayload: ["' OR 1=1 --", "' OR '1'='1"],
    flag: 'OGT{sql1_byp4ss_m4st3r}'
  },
  {
    id: '4',
    title: 'Alert Me!',
    category: ChallengeCategory.XSS,
    difficulty: Difficulty.EASY,
    points: 150,
    description: 'The search bar reflects your input directly onto the page. Can you execute a simple JavaScript alert to uncover the OGT flag?',
    hint: 'Use <script> tags.',
    solutionSteps: [
      'Identify the input field.',
      'Input <script>alert(1)</script>.',
      'See if the browser executes the script.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://search-portal.local',
    correctPayload: '<script>alert(1)</script>',
    flag: 'OGT{xss_f1rst_st3p}'
  },
  {
    id: '5',
    title: 'Directory Wanderer',
    category: ChallengeCategory.INJECTION,
    difficulty: Difficulty.MEDIUM,
    points: 250,
    description: 'The "file" parameter in the URL looks suspicious. Can you read the system /etc/passwd file to find an OGT secret?',
    hint: 'Try using ../ to move up directories.',
    solutionSteps: [
      'Analyze the URL: ?file=image.jpg.',
      'Replace image.jpg with ../../../etc/passwd.',
      'Examine the output for the flag.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://file-viewer.local',
    correctPayload: '../../../../etc/passwd',
    flag: 'OGT{p4th_tr4v3rs4l_suc3ss}'
  },
  {
    id: '6',
    title: 'Admin Impersonation',
    category: ChallengeCategory.AUTH,
    difficulty: Difficulty.MEDIUM,
    points: 200,
    description: 'The website identifies you using a cookie named "user_type". Can you become an admin to see the OGT flag?',
    hint: 'Check your browser cookies and change "guest" to "admin".',
    solutionSteps: [
      'Open browser Developer Tools (F12).',
      'Go to the Application/Storage tab.',
      'Find the "user_type" cookie and change its value to "admin".',
      'Refresh the page.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://dashboard.local',
    correctPayload: 'admin',
    flag: 'OGT{c00k13_m4n1pul4t0r}'
  },
  {
    id: '7',
    title: 'Hidden IDOR',
    category: ChallengeCategory.AUTH,
    difficulty: Difficulty.MEDIUM,
    points: 300,
    description: 'You can view your profile at /profile/105. Find the OGT flag on the admin profile.',
    hint: 'Try changing the ID in the URL.',
    solutionSteps: [
      'Check your profile URL.',
      'Decrement the ID number manually.',
      'Access the admin profile to find the flag.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://social-app.local/profile/105',
    correctPayload: '/profile/1',
    flag: 'OGT{1d0r_vulnerab1l1ty_found}'
  },
  {
    id: '8',
    title: 'Command Execution',
    category: ChallengeCategory.INJECTION,
    difficulty: Difficulty.HARD,
    points: 450,
    description: 'A network diagnostic tool lets you ping IP addresses. Can you execute "ls" to find the OGT flag file?',
    hint: 'Use a semicolon (;) to chain commands.',
    solutionSteps: [
      'Enter an IP: 127.0.0.1.',
      'Append a command: 127.0.0.1; ls.',
      'Find the flag file in the list.'
    ],
    simulatorType: 'terminal',
    correctPayload: '; ls',
    flag: 'OGT{r3m0t3_c0mm4nd_3x3c}'
  },
  {
    id: '9',
    title: 'Weak Session ID',
    category: ChallengeCategory.AUTH,
    difficulty: Difficulty.MEDIUM,
    points: 200,
    description: 'Session IDs are just incremental numbers. Can you predict the next one and find the OGT user data?',
    hint: 'If your session is 100, try 101 or 99.',
    solutionSteps: [
      'Observe the session cookie format.',
      'Try modifying the cookie to a nearby integer.',
      'Hijack another session.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://bank.local',
    correctPayload: 'session=1',
    flag: 'OGT{s3ss10n_h1j4ck_101}'
  },
  {
    id: '10',
    title: 'Unrestricted Upload',
    category: ChallengeCategory.INJECTION,
    difficulty: Difficulty.HARD,
    points: 500,
    description: 'You can upload profile pictures. Upload a .php file to get an OGT shell!',
    hint: 'Upload a web shell to execute commands.',
    solutionSteps: [
      'Create a simple PHP shell.',
      'Upload it via the profile picture form.',
      'Navigate to the uploaded file and execute a command to find the flag.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://upload.local',
    correctPayload: 'shell.php',
    flag: 'OGT{php_sh3ll_upload}'
  },
  {
    id: '21',
    title: 'Template Injection',
    category: ChallengeCategory.INJECTION,
    difficulty: Difficulty.MEDIUM,
    points: 300,
    description: 'The server uses Jinja2 templates to greet you. Can you inject a mathematical expression to confirm Server-Side Template Injection (SSTI)?',
    hint: 'Try {{ 7 * 7 }}. If it shows 49, you have SSTI.',
    solutionSteps: [
      'Enter {{ 7*7 }} in the name field.',
      'Observe the output.',
      'Leak system config via {{ config.items() }}.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://greet.local',
    correctPayload: '{{7*7}}',
    flag: 'OGT{sst1_jinja2_exp0sed}'
  },
  {
    id: '22',
    title: 'Host Header Spoof',
    category: ChallengeCategory.WEB,
    difficulty: Difficulty.MEDIUM,
    points: 250,
    description: 'The server generates password reset links based on the Host header. Spoof it to receive the OGT reset token.',
    hint: 'Modify the Host header in your request.',
    solutionSteps: [
      'Intercept a password reset request.',
      'Change Host header to evil.com.',
      'Check the reset link generation.'
    ],
    simulatorType: 'browser',
    correctPayload: 'Host: evil.com',
    flag: 'OGT{h0st_h34d3r_p01s0n}'
  },
  {
    id: '23',
    title: 'Parameter Tampering',
    category: ChallengeCategory.LOGIC,
    difficulty: Difficulty.EASY,
    points: 150,
    description: 'The profile page uses ?role=user in the URL. Can you find the OGT flag by elevating your role?',
    hint: 'Change "user" to something more powerful.',
    solutionSteps: [
      'Navigate to the profile.',
      'Modify the URL parameter to ?role=admin.',
      'Find the flag on the admin dashboard.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://portal.local/user',
    correctPayload: 'role=admin',
    flag: 'OGT{param_tamp3r_suc3ss}'
  },
  {
    id: '24',
    title: 'GraphQL Introspection',
    category: ChallengeCategory.WEB,
    difficulty: Difficulty.MEDIUM,
    points: 300,
    description: 'The GraphQL endpoint has introspection enabled. Query the schema to find secret fields.',
    hint: 'Send a __schema query.',
    solutionSteps: [
      'Access /graphql.',
      'Send an introspection query.',
      'Find the hidden "secretFlag" field.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://api.local/graphql',
    correctPayload: '__schema',
    flag: 'OGT{gr4phql_leak_schemas}'
  },
  {
    id: '25',
    title: 'MD5 Collision',
    category: ChallengeCategory.AUTH,
    difficulty: Difficulty.MEDIUM,
    points: 200,
    description: 'The system uses weak MD5 hashes for session validation. Find a way to collide two values.',
    hint: 'Search for common MD5 collisions or weak hash implementations.',
    solutionSteps: [
      'Identify the hash function.',
      'Find two inputs that produce the same hash.',
      'Bypass the check.'
    ],
    simulatorType: 'browser',
    correctPayload: 'hash_collision',
    flag: 'OGT{w3ak_md5_cr4ck3d}'
  },
  {
    id: '26',
    title: 'Server Side Forgery',
    category: ChallengeCategory.INJECTION,
    difficulty: Difficulty.HARD,
    points: 500,
    description: 'The app fetches images from URLs. Can you perform an SSRF to access the internal metadata service at 169.254.169.254?',
    hint: 'Try fetching http://169.254.169.254/latest/meta-data/.',
    solutionSteps: [
      'Find the URL input field.',
      'Input the metadata IP address.',
      'Read the sensitive cloud credentials.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://proxy.local/fetch',
    correctPayload: '169.254.169.254',
    flag: 'OGT{ssrf_cl0ud_metadata}'
  },
  {
    id: '27',
    title: 'Prototype Poisoning',
    category: ChallengeCategory.XSS,
    difficulty: Difficulty.HARD,
    points: 450,
    description: 'A JSON.parse() implementation is vulnerable to prototype pollution. Overwrite the admin property globally.',
    hint: 'Use __proto__ in your JSON payload.',
    solutionSteps: [
      'Identify the vulnerable input.',
      'Craft a payload: {"__proto__": {"isAdmin": true}}.',
      'Trigger an admin action.'
    ],
    simulatorType: 'browser',
    correctPayload: '__proto__',
    flag: 'OGT{pr0t0_p0llut1on_rce}'
  },
  {
    id: '28',
    title: 'API Info Leak',
    category: ChallengeCategory.WEB,
    difficulty: Difficulty.EASY,
    points: 100,
    description: 'Common API endpoints are often unprotected. Find the OGT flag on the /v1/debug endpoint.',
    hint: 'Try common paths like /api, /debug, or /status.',
    solutionSteps: [
      'Guess standard API paths.',
      'Navigate to /api/v1/debug.',
      'Examine the JSON response.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://api-test.local',
    correctPayload: '/api/v1/debug',
    flag: 'OGT{api_d3bug_inf0_l3ak}'
  },
  {
    id: '29',
    title: 'JWT Secret Brute',
    category: ChallengeCategory.AUTH,
    difficulty: Difficulty.MEDIUM,
    points: 350,
    description: 'The JWT secret is a common word. Brute force it and forge a token for "admin".',
    hint: 'The secret is "secret". Seriously.',
    solutionSteps: [
      'Decode the JWT.',
      'Brute force the signature secret.',
      'Modify the payload and resign.'
    ],
    simulatorType: 'browser',
    correctPayload: 'admin',
    flag: 'OGT{jwt_brut3_f0rc3d}'
  },
  {
    id: '30',
    title: 'Hidden Subdomain',
    category: ChallengeCategory.WEB,
    difficulty: Difficulty.EASY,
    points: 100,
    description: 'Check the subdomains! Developers often forget to secure dev.ogt.local.',
    hint: 'Check the SSL certificate or try common subdomains.',
    solutionSteps: [
      'Enumerate subdomains.',
      'Access dev.ogt.local.',
      'Retrieve the flag from the dev environment.'
    ],
    simulatorType: 'browser',
    targetUrl: 'http://ogt.local',
    correctPayload: 'dev.ogt.local',
    flag: 'OGT{subd0m41n_found}'
  }
];
