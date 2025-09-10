import os
import yaml
import re
import sys
import requests
import subprocess
import tempfile
import hcl2
from packaging import version

registry_cache = {}
private_cache = {}
module_usages = []  # Each item: {'parent_org': ..., 'parent_repo': ..., 'parent_module': ..., 'source': ..., 'version': ...}
unique_modules = {}  # Key: (source, version), Value: [list of usages]
module_results = {}  # Key: (source, version), Value: scan results
repo_cache = {}  # Key: (repo_url, version), Value: (all_tf_contents, api_error)


ENTERPRISE_URL = os.environ.get("ENTERPRISE_URL")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_TOKEN_ENTERPRISE = os.environ.get("GITHUB_TOKEN_ENTERPRISE")

if not GITHUB_TOKEN and not GITHUB_TOKEN_ENTERPRISE:
    raise RuntimeError("At least one of GITHUB_TOKEN or GITHUB_TOKEN_ENTERPRISE must be set.")

if GITHUB_TOKEN_ENTERPRISE and not ENTERPRISE_URL:
    print("\n" + "=" * 80)
    print("Enterprise GitHub token detected, but no Enterprise URL is set.")
    print("Please enter your Enterprise GitHub URL (e.g., github.mycompany.com):")
    print("=" * 80)
    
    try:
        input_url = input("Enterprise URL > ").strip()
        
        # Strip http:// or https:// if the user included them
        if input_url.startswith("http://"):
            input_url = input_url[7:]
        elif input_url.startswith("https://"):
            input_url = input_url[8:]
        
        # Validate the input URL (basic check)
        if not input_url or "//" in input_url or " " in input_url:
            print("Invalid Enterprise URL. Please set the ENTERPRISE_URL environment variable and try again.")
            sys.exit(1)
        
        ENTERPRISE_URL = input_url
        print(f"Using Enterprise URL: {ENTERPRISE_URL}")
        
        # Update the environment variable for subprocesses
        os.environ["ENTERPRISE_URL"] = ENTERPRISE_URL
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error getting Enterprise URL: {str(e)}")
        print("Please set the ENTERPRISE_URL environment variable and try again.")
        sys.exit(1)

if ENTERPRISE_URL and not GITHUB_TOKEN_ENTERPRISE:
    print("\n" + "=" * 80)
    print(f"Enterprise GitHub URL ({ENTERPRISE_URL}) is set, but no Enterprise GitHub token is provided.")
    print("Please enter your Enterprise GitHub token (will not be displayed):")
    print("=" * 80)
    
    try:
        import getpass
        token = getpass.getpass("Enterprise GitHub token > ")
        
        # Validate the input token (basic check)
        if not token or len(token) < 10:  # Most GitHub tokens are much longer
            print("Invalid GitHub token. Please set the GITHUB_TOKEN_ENTERPRISE environment variable and try again.")
            sys.exit(1)
        
        GITHUB_TOKEN_ENTERPRISE = token
        print("Enterprise GitHub token accepted.")
        
        # Update the environment variable for subprocesses
        os.environ["GITHUB_TOKEN_ENTERPRISE"] = GITHUB_TOKEN_ENTERPRISE
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error getting Enterprise GitHub token: {str(e)}")
        print("Please set the GITHUB_TOKEN_ENTERPRISE environment variable and try again.")
        sys.exit(1)

def get_headers(source_url):
    # Use enterprise token if source_url contains ENTERPRISE_URL, else use public token
    if ENTERPRISE_URL in source_url:
        token = GITHUB_TOKEN_ENTERPRISE
    else:
        token = GITHUB_TOKEN
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

DEBUG = (
    "-d" in sys.argv
    or "--debug" in sys.argv
)

tmp_root = None
for i, arg in enumerate(sys.argv):
    if arg == "--folder" and i + 1 < len(sys.argv):
        tmp_root = sys.argv[i + 1]
        break

def is_version_compatible(constraint, target_version):
    """
    Check if target_version satisfies the constraint.
    Returns (is_compatible, reason)
    """
    try:
        # Clean up constraint string
        constraint = constraint.strip()
        target_version = target_version.strip()
        
        # Handle common constraint formats
        if constraint.startswith(">="):
            min_version = constraint[2:].strip()
            return version.parse(target_version) >= version.parse(min_version), f"requires >= {min_version}"
        elif constraint.startswith("<="):
            max_version = constraint[2:].strip()
            return version.parse(target_version) <= version.parse(max_version), f"requires <= {max_version}"
        elif constraint.startswith(">"):
            min_version = constraint[1:].strip()
            return version.parse(target_version) > version.parse(min_version), f"requires > {min_version}"
        elif constraint.startswith("<"):
            max_version = constraint[1:].strip()
            return version.parse(target_version) < version.parse(max_version), f"requires < {max_version}"
        elif constraint.startswith("~>"):
            # Pessimistic constraint
            base_version = constraint[2:].strip()
            base = version.parse(base_version)
            target = version.parse(target_version)
            # ~> 1.3.0 means >= 1.3.0 and < 1.4.0
            next_minor = version.Version(f"{base.major}.{base.minor + 1}.0")
            return base <= target < next_minor, f"requires ~> {base_version}"
        elif "," in constraint:
            # Multiple constraints (e.g., ">= 1.3.0, < 1.7.0")
            constraints = [c.strip() for c in constraint.split(",")]
            for c in constraints:
                compatible, reason = is_version_compatible(c, target_version)
                if not compatible:
                    return False, reason
            return True, "satisfies all constraints"
        else:
            # Exact version
            return version.parse(target_version) == version.parse(constraint), f"requires exactly {constraint}"
    except Exception as e:
        return False, f"invalid constraint format: {constraint}"

def analyze_terraform_compatibility(module_results, unique_modules, target_version):
    """
    Analyze all collected constraints against target Terraform version.
    Returns (compatible_modules, incompatible_modules)
    """
    compatible_modules = []
    incompatible_modules = []
    
    for (source, module_version), constraints in module_results.items():
    
        parent_usages = unique_modules.get((source, module_version), [])

        for constraint_info in constraints:
            if "required_version" in constraint_info:
                tf_constraint = constraint_info["required_version"]
                file_path = constraint_info.get("file", "unknown")
                
                is_compatible, reason = is_version_compatible(tf_constraint, target_version)
                
                module_info = {
                    "source": source,
                    "version": module_version,
                    "file": file_path,
                    "constraint": tf_constraint,
                    "reason": reason,
                    "parent_usages": parent_usages  # Add parent usage info
                }
                
                if is_compatible:
                    compatible_modules.append(module_info)
                else:
                    incompatible_modules.append(module_info)
    
    return compatible_modules, incompatible_modules

def get_yaml_repos(yaml_path):
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
        if not data:
            return [], None
        repositories = data.get("repositories", [])
        terraform_version = data.get("terraform_version")
        return repositories, terraform_version

def get_team_repos(source_url, team_slug):
    org_name = source_url.rstrip("/").split("/")[-1]
    team_api_url = f"https://{ENTERPRISE_URL}/api/v3/orgs/{org_name}/teams/{team_slug}/repos"
    resp = requests.get(team_api_url, headers=get_headers(source_url))
    resp.raise_for_status()
    return [repo["name"] for repo in resp.json()]

def get_org_repos(source_url):
    org_name = source_url.rstrip("/").split("/")[-1]
    repos = []
    page = 1
    while True:
        api_url = f"https://{ENTERPRISE_URL}/api/v3/orgs/{org_name}/repos?per_page=100&page={page}"
        resp = requests.get(api_url, headers=get_headers(source_url))
        resp.raise_for_status()
        data = resp.json()
        if not data:
            break
        repos.extend([repo["name"] for repo in data])
        page += 1
    return repos

def validate_repo_entry(entry):
    if not entry.get("list") and not entry.get("pattern"):
        raise ValueError(
            f"Each repository entry must have either 'list' or 'pattern'. Entry: {entry}"
        )

def clone_repo(source_url, repo_name, dest_dir):
    repo_url = f"{source_url.rstrip('/')}/{repo_name}.git"
    subprocess.run(["git", "init", "--initial-branch=main", dest_dir], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
    subprocess.run(["git", "-C", dest_dir, "remote", "add", "origin", repo_url], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
    subprocess.run(["git", "-C", dest_dir, "config", "advice.detachedHead", "false"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(["git", "-C", dest_dir, "config", "core.sparseCheckout", "true"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
    sparse_file = os.path.join(dest_dir, ".git", "info", "sparse-checkout")
    with open(sparse_file, "w") as f:
        f.write("*.tf\n**/*.tf\n")
    subprocess.run(["git", "-C", dest_dir, "pull", "--depth", "1", "origin", "HEAD"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)

def parse_registry_source(source):
    """Parse Terraform registry source format: namespace/name/provider[//submodule]"""
    if not source:
        return None, None, None, None
    
    # Split on // to separate main module from submodule
    parts = source.split('//')
    main_module = parts[0]
    submodule = parts[1] if len(parts) > 1 else None
    
    # Parse the main module part
    components = main_module.split('/')
    if len(components) == 3:
        namespace, name, provider = components
        return namespace, name, provider, submodule
    return None, None, None, None

def get_repo_contents_cached(repo_url, version):
    """Get all .tf files from a repo with caching"""
    cache_key = (repo_url, version)
    if cache_key not in repo_cache:
        if DEBUG:
            print(f"[DEBUG] Downloading repo contents (new): {repo_url} (version: {version})")
        tf_contents, api_error = fetch_tf_files_from_github_api(repo_url, version)
        repo_cache[cache_key] = (tf_contents, api_error)
    else:
        if DEBUG:
            print(f"[DEBUG] Using cached repo contents: {repo_url} (version: {version})")
    return repo_cache[cache_key]

def fetch_tf_files_from_github_api(source_url, version=None):
    if DEBUG:
        print(f"[DEBUG] fetch_tf_files_from_github_api called with source_url: {source_url}, version: {version}")
    src_info = parse_github_source_url(source_url)
    if DEBUG:
        print(f"[DEBUG] parse_github_source_url result: {src_info}")
    if not src_info or not src_info["org"] or not src_info["repo"]:
        return [], "Invalid source info"
    # Detect GHE vs public GitHub
    if ENTERPRISE_URL in source_url:
        api_base = f"https://{ENTERPRISE_URL}/api/v3"
    else:
        api_base = "https://api.github.com"
    # Always fetch repo info to determine default branch
    repo_url = f"{api_base}/repos/{src_info['org']}/{src_info['repo']}"
    repo_resp = requests.get(repo_url, headers=get_headers(source_url))
    if repo_resp.status_code != 200:
        error_msg = f"Failed to fetch repo info {repo_url} ({repo_resp.status_code})\nResponse: {repo_resp.text}"
        return [], error_msg
    repo_data = repo_resp.json()
    sha = None
    # If ref is present, treat as branch
    if src_info["ref"]:
        branch_url = f"{api_base}/repos/{src_info['org']}/{src_info['repo']}/branches/{src_info['ref']}"
        branch_resp = requests.get(branch_url, headers=get_headers(source_url))
        if branch_resp.status_code == 200:
            branch_data = branch_resp.json()
            sha = branch_data.get("commit", {}).get("sha")
        else:
            error_msg = f"Failed to fetch branch info {branch_url} ({branch_resp.status_code})\nResponse: {branch_resp.text}"
            return [], error_msg
    # If version is present, treat as tag
    elif version:
        # Check if version looks like a semantic version (tags) vs branch name
        if re.match(r'^\d+\.\d+', version):
            # Treat as version tag - try direct tag lookup
            for tag_name in [f"v{version}", version]:
                tag_ref_url = f"{api_base}/repos/{src_info['org']}/{src_info['repo']}/git/refs/tags/{tag_name}"
                if DEBUG:
                    print(f"[DEBUG] Trying direct tag lookup: {tag_ref_url}")
                tag_resp = requests.get(tag_ref_url, headers=get_headers(source_url))
                if tag_resp.status_code == 200:
                    tag_data = tag_resp.json()
                    sha = tag_data["object"]["sha"]
                    if DEBUG:
                        print(f"[DEBUG] Found tag {tag_name} -> {sha}")
                    break
            
            if not sha:
                if DEBUG:
                    print(f"[DEBUG] Neither 'v{version}' nor '{version}' tag found")
                error_msg = f"Tag 'v{version}' or '{version}' not found"
                return [], error_msg
        else:
            # Treat as branch name (like "development", "main", "testing", etc.)
            branch_url = f"{api_base}/repos/{src_info['org']}/{src_info['repo']}/branches/{version}"
            if DEBUG:
                print(f"[DEBUG] Trying branch lookup: {branch_url}")
            branch_resp = requests.get(branch_url, headers=get_headers(source_url))
            if branch_resp.status_code == 200:
                branch_data = branch_resp.json()
                sha = branch_data.get("commit", {}).get("sha")
                if DEBUG:
                    print(f"[DEBUG] Found branch {version} -> {sha}")
            else:
                if DEBUG:
                    print(f"[DEBUG] Branch '{version}' not found")
                error_msg = f"Branch '{version}' not found"
                return [], error_msg

    if not sha:
        return [], f"Could not get commit SHA for branch/tag/default"

    # Get the full tree recursively
    tree_url = f"{api_base}/repos/{src_info['org']}/{src_info['repo']}/git/trees/{sha}?recursive=1"
    tree_resp = requests.get(tree_url, headers=get_headers(source_url))
    if tree_resp.status_code != 200:
        error_msg = f"Failed to fetch tree {tree_url} ({tree_resp.status_code})\nResponse: {tree_resp.text}"
        return [], error_msg
    tree_data = tree_resp.json()
    tf_files = [item for item in tree_data.get("tree", []) if item["path"].endswith(".tf") and item["type"] == "blob"]
    if DEBUG:
        print(f"[DEBUG] Found {len(tf_files)} .tf files in tree for {src_info['org']}/{src_info['repo']} (sha={sha})")
        for item in tf_files:
            print(f"[DEBUG] .tf file: {item['path']}")
    tf_contents = []
    for tf_file in tf_files:
        file_url = f"{api_base}/repos/{src_info['org']}/{src_info['repo']}/contents/{tf_file['path']}?ref={sha}"
        file_resp = requests.get(file_url, headers=get_headers(source_url))
        if file_resp.status_code == 200:
            content = file_resp.json().get("content")
            if content:
                import base64
                tf_contents.append((tf_file["path"], base64.b64decode(content).decode("utf-8")))
        else:
            error_msg = f"Failed to download {file_url} ({file_resp.status_code})\nResponse: {file_resp.text}"
            return [], error_msg
    return tf_contents, None

def normalize_module_key(source, version):
    """
    Normalize the module source for deduplication.
    Handle both registry modules and direct Git URLs.
    """
    if not source:
        return (None, version)
    
    # Remove git:: prefix
    if source.startswith('git::'):
        source = source.replace('git::', '')
    
    # Parse registry source to get base repo URL
    ns, name, provider, submodule = parse_registry_source(source)
    
    if ns and name and provider:
        # For registry modules, get the GitHub repo URL
        registry_url = get_registry_module_source(ns, name, provider)
        if registry_url:
            repo_url = registry_url
            # Include submodule in the key to differentiate submodules
            if submodule:
                repo_url = f"{registry_url}//{submodule}"
        else:
            repo_url = source
    else:
        # Extract repo URL for direct Git URLs (ignore subdirectory and query params except ref)
        if ENTERPRISE_URL:
            repo_pattern = (
                rf"(git@{re.escape(ENTERPRISE_URL)}:[^/]+/[^/.]+\.git"
                rf"|https://{re.escape(ENTERPRISE_URL)}/[^/]+/[^/.]+\.git"
                r"|https://github\.com/[^/]+/[^/.]+\.git)"
            )
        else:
            # Only include GitHub.com patterns when ENTERPRISE_URL is not set
            repo_pattern = r"(https://github\.com/[^/]+/[^/.]+\.git)"
        repo_match = re.match(repo_pattern, source)
        repo_url = repo_match.group(1) if repo_match else source
        
        # Include submodule path in the key if present
        if '//' in source:
            repo_url = source  # Keep the full source with submodule path
    
    # Extract ref from ?ref=... if present
    ref_match = re.search(r"ref=([^\s/&]+)", source)
    ref = ref_match.group(1) if ref_match else None
    
    # Use ref if present, else use version
    key_version = ref if ref else version
    
    return (repo_url, key_version)

def scan_module_version_dependencies_api(source_url, version):
    # Extract submodule path if present (only split on // AFTER the domain)
    if '//' in source_url and source_url.count('//') > 1:
        # Find the position after https://domain.com/ to look for submodule //
        protocol_end = source_url.find('//') + 2  # Position after https://
        domain_and_path = source_url[protocol_end:]
        
        if '/' in domain_and_path:
            first_slash = domain_and_path.find('/')
            remainder = domain_and_path[first_slash:]
            
            if '//' in remainder:
                # Found submodule path
                base_url = source_url[:protocol_end + first_slash + remainder.find('//')]
                submodule_path = remainder[remainder.find('//') + 2:]
                if DEBUG:
                    print(f"[DEBUG] API method extracting submodule path: {submodule_path} from {source_url}")
            else:
                base_url = source_url
                submodule_path = None
        else:
            base_url = source_url
            submodule_path = None
    else:
        base_url = source_url
        submodule_path = None

    # Use cached repo contents
    tf_contents, api_error = get_repo_contents_cached(base_url, version)
    if api_error:
        if DEBUG:
            print(f"[DEBUG] API error: {api_error}")
        return []
    
    version_constraints = []
    for file_name, tf_text in tf_contents:
        # Filter files to only those in the submodule path if specified
        if submodule_path and not file_name.startswith(submodule_path + '/'):
            continue
            
        if "example" in file_name.lower():
            if DEBUG:
                print(f"[DEBUG] Skipping example file: {file_name}")
            continue
            
        try:
            obj = hcl2.loads(tf_text)
        except Exception:
            continue
        if "terraform" in obj:
            for block in obj["terraform"]:
                if "required_version" in block:
                    version_constraints.append({"file": "/" + file_name, "required_version": block["required_version"]})
        if "provider" in obj:
            for provider_block in obj["provider"]:
                for provider_name, attrs in provider_block.items():
                    if "version" in attrs:
                        version_constraints.append({"file": "/" + file_name, "provider": provider_name, "version": attrs["version"]})
    
    if DEBUG:
        print(f"[DEBUG] Found {len(version_constraints)} constraints in submodule: {submodule_path or 'root'}")
    
    return version_constraints

def get_registry_module_source(namespace, name, provider):
    url = f"https://registry.terraform.io/v1/modules/{namespace}/{name}/{provider}"
    resp = requests.get(url)
    if resp.status_code == 200:
        data = resp.json()
        return data.get('source')
    return None

def scan_module_version_dependencies(source_url, version):
    # Only handle public GitHub for now
    match = re.match(r"https://github.com/(?P<org>[^/]+)/(?P<repo>[^/.]+)", source_url)
    if not match:
        print(f"      Could not parse public GitHub source URL: {source_url}")
        return []
    org = match.group("org")
    repo = match.group("repo")
    repo_url = f"https://github.com/{org}/{repo}.git"
    with tempfile.TemporaryDirectory(prefix=".") as tmpdir:
        subprocess.run(["git", "init", "--initial-branch=main", tmpdir], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        subprocess.run(["git", "-C", tmpdir, "remote", "add", "origin", repo_url], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        subprocess.run(["git", "-C", tmpdir, "config", "advice.detachedHead", "false"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(["git", "-C", tmpdir, "config", "core.sparseCheckout", "true"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        sparse_file = os.path.join(tmpdir, ".git", "info", "sparse-checkout")
        with open(sparse_file, "w") as f:
            f.write("*.tf\n**/*.tf\n")
        ref_v = f"v{version}" if version else "HEAD"
        ref_plain = version if version else "HEAD"
        if DEBUG:
            print(f"[DEBUG] Trying tag: {ref_v} and {ref_plain} for repo {repo_url}")
        checked_out = False
        try:
            # Explicitly fetch the tag with v prefix
            subprocess.run(["git", "-C", tmpdir, "fetch", "origin", f"refs/tags/{ref_v}:refs/tags/{ref_v}"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
            subprocess.run(["git", "-C", tmpdir, "checkout", ref_v], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
            checked_out = True
        except subprocess.CalledProcessError:
            if DEBUG:
                print(f"      Could not fetch or checkout tag '{ref_v}' in {source_url}, trying without 'v' prefix.")
            try:
                # Explicitly fetch the tag without v prefix
                subprocess.run(["git", "-C", tmpdir, "fetch", "origin", f"refs/tags/{ref_plain}:refs/tags/{ref_plain}"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
                subprocess.run(["git", "-C", tmpdir, "checkout", ref_plain], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
                checked_out = True
            except subprocess.CalledProcessError:
                print(f"      Could not fetch or checkout tag '{ref_v}' or '{ref_plain}' in {source_url}, using default branch.")
                subprocess.run(["git", "-C", tmpdir, "pull", "--depth", "1", "origin", "HEAD"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        tf_files = find_tf_files(tmpdir)
        version_constraints = []
        for tf_file in tf_files:
            if "example" in tf_file.lower():
                if DEBUG:
                    print(f"[DEBUG] Skipping example file: {tf_file}")
                continue
            with open(tf_file, "r") as f:
                try:
                    obj = hcl2.load(f)
                except Exception:
                    continue
                # Check for terraform required_version
                if "terraform" in obj:
                    for block in obj["terraform"]:
                        if "required_version" in block:
                            version_constraints.append({"file": tf_file, "required_version": block["required_version"]})
                # Check for provider version constraints
                if "provider" in obj:
                    for provider_block in obj["provider"]:
                        for provider_name, attrs in provider_block.items():
                            if "version" in attrs:
                                version_constraints.append({"file": tf_file, "provider": provider_name, "version": attrs["version"]})
            if DEBUG:
                print(f"[DEBUG] Parsing file: {tf_file}")
        return version_constraints

def scan_private_module(source_url, ref=None, version=None):
    repo_url, subdir, parsed_ref = parse_private_source(source_url)
    if not repo_url:
        print(f"      Invalid repo URL: {source_url}")
        return []
    
    # Use parsed ref from URL if no explicit ref provided
    if not ref and parsed_ref:
        ref = parsed_ref
        
    with tempfile.TemporaryDirectory(prefix=".") as tmpdir:
        subprocess.run(["git", "init", "--initial-branch=main", tmpdir], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        subprocess.run(["git", "-C", tmpdir, "remote", "add", "origin", repo_url], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        subprocess.run(["git", "-C", tmpdir, "config", "advice.detachedHead", "false"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(["git", "-C", tmpdir, "config", "core.sparseCheckout", "true"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True)
        sparse_file = os.path.join(tmpdir, ".git", "info", "sparse-checkout")
        if subdir:
            with open(sparse_file, "w") as f:
                f.write(f"{subdir}/*.tf\n{subdir}/**/*.tf\n")
        else:
            with open(sparse_file, "w") as f:
                f.write("*.tf\n**/*.tf\n")
        env = os.environ.copy()
        env["GIT_ASKPASS"] = "echo"
        env["GIT_TERMINAL_PROMPT"] = "0"
        # Only set tokens if they exist
        if GITHUB_TOKEN:
            env["GITHUB_TOKEN"] = GITHUB_TOKEN

        checked_out = False
        subprocess.run(["git", "-C", tmpdir, "fetch", "--tags", "origin"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True, env=env)
        
        # Prioritize ref (branch) over version (tag)
        if ref:
            try:
                subprocess.run(["git", "-C", tmpdir, "checkout", ref], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True, env=env)
                checked_out = True
                if DEBUG:
                    print(f"[DEBUG] Successfully checked out branch: {ref}")
            except subprocess.CalledProcessError:
                if DEBUG:
                    print(f"[DEBUG] Could not checkout branch/ref '{ref}' in {repo_url}")
        
        # If no ref, try version as tag
        if not checked_out and version:
            # Check if it looks like a semantic version (contains dots) vs branch name
            if re.match(r'^\d+\.\d+', version):
                # Treat as version tag - try both v prefix and without
                for tag_variant in [f"v{version}", version]:
                    try:
                        subprocess.run(["git", "-C", tmpdir, "checkout", tag_variant], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True, env=env)
                        checked_out = True
                        if DEBUG:
                            print(f"[DEBUG] Successfully checked out tag: {tag_variant}")
                        break
                    except subprocess.CalledProcessError:
                        continue
                if not checked_out and DEBUG:
                    print(f"[DEBUG] Could not checkout version tag '{version}' (tried 'v{version}' and '{version}')")
            else:
                # Treat as branch name (like "development", "main", etc.)
                try:
                    subprocess.run(["git", "-C", tmpdir, "checkout", version], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True, env=env)
                    checked_out = True
                    if DEBUG:
                        print(f"[DEBUG] Successfully checked out branch: {version}")
                except subprocess.CalledProcessError:
                    if DEBUG:
                        print(f"[DEBUG] Could not checkout branch '{version}' in {repo_url}")
        
        # Fallback to default branch
        if not checked_out:
            try:
                subprocess.run(["git", "-C", tmpdir, "pull", "--depth", "1", "origin", "HEAD"], stdout=None if DEBUG else subprocess.DEVNULL, stderr=None if DEBUG else subprocess.DEVNULL, check=True, env=env)
                if DEBUG:
                    print(f"[DEBUG] Using default branch")
            except subprocess.CalledProcessError:
                print(f"      Could not pull default branch for {repo_url}")
                return []
        
        tf_files = find_tf_files(tmpdir)
        version_constraints = []
        for tf_file in tf_files:
            if "example" in tf_file.lower():
                if DEBUG:
                    print(f"[DEBUG] Skipping example file: {tf_file}")
                continue
            with open(tf_file, "r") as f:
                try:
                    obj = hcl2.load(f)
                except Exception:
                    continue
                if "terraform" in obj:
                    for block in obj["terraform"]:
                        if "required_version" in block:
                            version_constraints.append({"file": tf_file, "required_version": block["required_version"]})
                if "provider" in obj:
                    for provider_block in obj["provider"]:
                        for provider_name, attrs in provider_block.items():
                            if "version" in attrs:
                                version_constraints.append({"file": tf_file, "provider": provider_name, "version": attrs["version"]})
        return version_constraints

def print_progress(current, total, bar_length=40, message="Progress"):
    percent = float(current) / total
    # Cap at 99% until done
    if current < total:
        percent = min(percent, 0.99)
    arrow = '-' * int(round(percent * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    sys.stdout.write(f"\r{message}: [{arrow}{spaces}] {int(percent * 100)}% ({current}/{total})")
    sys.stdout.flush()

def find_tf_files(repo_path):
    tf_files = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".tf"):
                tf_files.append(os.path.join(root, file))
    return tf_files

def parse_modules(tf_file):
    modules = []
    with open(tf_file, "r") as f:
        try:
            obj = hcl2.load(f)
        except Exception:
            return modules
        for block in obj.get("module", []):
            for name, attrs in block.items():
                source = attrs.get("source")
                version = attrs.get("version")
                modules.append({"name": name, "source": source, "version": version})
    return modules

def parse_github_source_url(source_url):
    """
    Robustly parse GitHub and GitHub Enterprise repo URLs.
    Returns dict with org, repo, path, ref.
    """
    patterns = []
    
    # Only add enterprise patterns if ENTERPRISE_URL is set
    if ENTERPRISE_URL:
        patterns.extend([
            # git::https://<ENTERPRISE_URL>/org/repo.git//subdir?ref=branch
            rf"^(?:git::)?https://{re.escape(ENTERPRISE_URL)}/(?P<org>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?(?:\/\/(?P<path>[^?]+))?(?:\?ref=(?P<ref>[^&]+))?",
            # https://<ENTERPRISE_URL>/org/repo.git?ref=branch
            rf"^https://{re.escape(ENTERPRISE_URL)}/(?P<org>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?(?:\?ref=(?P<ref>[^&]+))?",
            # git@<ENTERPRISE_URL>:org/repo.git?ref=branch
            rf"^git@{re.escape(ENTERPRISE_URL)}:(?P<org>[^/]+)/(?P<repo>[^/.]+)\.git(?:\?ref=(?P<ref>[^&]+))?",
        ])
    
    # Always add public GitHub patterns
    patterns.extend([
        # https://github.com/org/repo.git//subdir?ref=branch
        r"^(?:git::)?https://github\.com/(?P<org>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?(?:\/\/(?P<path>[^?]+))?(?:\?ref=(?P<ref>[^&]+))?",
        # https://github.com/org/repo.git?ref=branch
        r"^https://github\.com/(?P<org>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?(?:\?ref=(?P<ref>[^&]+))?",
        # git@github.com:org/repo.git?ref=branch
        r"^git@github\.com:(?P<org>[^/]+)/(?P<repo>[^/.]+)\.git(?:\?ref=(?P<ref>[^&]+))?",
    ])

    for pat in patterns:
        match = re.match(pat, source_url)
        if match:
            return {
                "org": match.group("org"),
                "repo": match.group("repo"),
                "path": match.group("path") if "path" in match.groupdict() else None,
                "ref": match.group("ref") if "ref" in match.groupdict() else None
            }
    return None

def get_module_dependencies_from_github(org, repo, ref=None, path=None):
    
    # Construct source_url from org and repo parameters
    source_url = f"https://github.com/{org}/{repo}"
    
    # If using enterprise GitHub, use that URL instead
    if ENTERPRISE_URL:
        source_url = f"https://{ENTERPRISE_URL}/{org}/{repo}"
    
    # Use GitHub API to get files at ref (tag/branch/commit)
    api_url = f"https://api.github.com/repos/{org}/{repo}/contents"
    if path:
        api_url += f"/{path}"
    params = {}
    if ref:
        params["ref"] = ref

    # Now source_url is defined for get_headers
    resp = requests.get(api_url, headers=get_headers(source_url), params=params)
    if resp.status_code != 200:
        print(f"Failed to fetch {api_url} ({resp.status_code})")
        return []
    files = resp.json()
    tf_files = [f for f in files if f["name"].endswith(".tf")]
    dependencies = []
    for tf_file in tf_files:
        file_resp = requests.get(tf_file["download_url"], headers=get_headers(source_url))
        if file_resp.status_code == 200:
            try:
                obj = hcl2.loads(file_resp.text)
                for block in obj.get("module", []):
                    for name, attrs in block.items():
                        source = attrs.get("source")
                        version = attrs.get("version")
                        dependencies.append({"name": name, "source": source, "version": version})
            except Exception:
                continue
    return dependencies


def color_text(text, color):
    colors = {
        "violet": "\033[95m",
        "yellow": "\033[93m",
        "reset": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def parse_private_source(source_url):
    # Remove git:: prefix if present
    source_url = re.sub(r'^git::', '', source_url)
    # Extract repo URL, subdir, and ref
    repo_url = None
    subdir = None
    ref = None

    # Only use enterprise URL patterns if ENTERPRISE_URL is set
    if ENTERPRISE_URL:
        # SSH format: git@github.contoso.com:org/repo.git?ref=branch
        ssh_pattern = rf"git@{re.escape(ENTERPRISE_URL)}:([^/]+)/([^/.]+)\.git(\?ref=([^\s/]+))?"
        ssh_match = re.match(ssh_pattern, source_url)
        if ssh_match:
            org = ssh_match.group(1)
            repo = ssh_match.group(2)
            repo_url = f"https://{ENTERPRISE_URL}/{org}/{repo}.git"
            ref = ssh_match.group(4)
        else:
            # HTTPS format: https://github.contoso.com/org/repo.git//subdir?ref=branch
            https_pattern = rf"(https://{re.escape(ENTERPRISE_URL)}/[^/]+/[^/.]+\.git)(//([^\?]+))?(\?ref=([^\s/]+))?"
            https_match = re.match(https_pattern, source_url)
            if https_match:
                repo_url = https_match.group(1)
                subdir = https_match.group(3)
                ref = https_match.group(5)

    return repo_url, subdir, ref

def parse_version_constraint(constraint):
    # Extract minimum and maximum from constraint strings like ">= 1.0.0, < 2.0.0"
    min_version = None
    max_version = None
    for part in constraint.split(","):
        part = part.strip()
        if part.startswith(">="):
            v = re.findall(r"\d+\.\d+\.\d+", part)
            if v:
                min_version = tuple(map(int, v[0].split(".")))
        elif part.startswith(">"):
            v = re.findall(r"\d+\.\d+\.\d+", part)
            if v:
                # > means next patch after this, but for summary we just show the number
                min_version = tuple(map(int, v[0].split(".")))
        elif part.startswith("<"):
            v = re.findall(r"\d+\.\d+\.\d+", part)
            if v:
                max_version = tuple(map(int, v[0].split(".")))
        elif part.startswith("<="):
            v = re.findall(r"\d+\.\d+\.\d+", part)
            if v:
                max_version = tuple(map(int, v[0].split(".")))
    return min_version, max_version

def find_min_max_constraints(scan_results):
    min_versions = []
    max_versions = []
    details = []
    for org, repos in scan_results.items():
        for repo, modules in repos.items():
            for mod in modules:
                for dep in mod.get("dependencies", []):
                    if "required_version" in dep:
                        min_v, max_v = parse_version_constraint(dep["required_version"])
                        if min_v:
                            min_versions.append((min_v, mod["name"], repo, org, dep["required_version"]))
                        if max_v:
                            max_versions.append((max_v, mod["name"], repo, org, dep["required_version"]))
    return min_versions, max_versions

def main():
    print(r"""
   __                            __                              __
  / /_ ___   _____ _____ ____ _ / /_   ____   __  __ ____   ____/ /
 / __// _ \ / ___// ___// __ '// __ \ / __ \ / / / // __ \ / __  / 
/ /_ /  __// /   / /   / /_/ // /_/ // /_/ // /_/ // / / // /_/ /  
\__/ \___//_/   /_/    \__,_//_.___/ \____/ \__,_//_/ /_/ \__,_/   
                TerraBound v1.1.0 by frankie@ibm.com                                                  
    """)
    print("\n Find all your terraform version constraints.\n")

    yaml_path = "repositories.yaml"
    repos_config, target_terraform_version = get_yaml_repos(yaml_path)
    all_results = {}

    if DEBUG:
        print(f"[DEBUG] Target Terraform version: {target_terraform_version}")
    
    # Calculate total parent repos to process
    total_parent_repos = 0
    for entry in repos_config:
        validate_repo_entry(entry)
        source_url = entry["org"]
        team = entry.get("team")
        pattern = entry.get("pattern")
        repo_list = entry.get("list", [])
        org_name = source_url.rstrip("/").split("/")[-1]
        matched_repos = set()
        if team:
            team_slug = team
            team_repos = get_team_repos(source_url, team_slug)
            if repo_list:
                matched_repos.update([r for r in team_repos if r in repo_list])
            elif pattern:
                matched_repos.update([r for r in team_repos if re.match(pattern, r)])
            else:
                matched_repos.update(team_repos)
        else:
            org_repos = get_org_repos(source_url)
            if pattern:
                matched_repos.update([r for r in org_repos if re.match(pattern, r)])
            if repo_list:
                matched_repos.update([r for r in org_repos if r in repo_list])
        if repo_list and not pattern and not team:
            matched_repos.update(repo_list)
        all_results[org_name] = sorted(matched_repos)
        total_parent_repos += len(matched_repos)

    # Step 1: Scan all parent repos and collect all module usages
    module_usages = []
    current_progress = 0
    print_progress(0, total_parent_repos, message="Scanning repositories")
    for org, repos in all_results.items():
        for repo in repos:
            if DEBUG:
                print(f"\n[DEBUG] Fetching .tf files from parent repo via GitHub API: {org}/{repo}")
            api_url = f"https://{ENTERPRISE_URL}/{org}/{repo}.git"
            tf_contents, api_error = fetch_tf_files_from_github_api(api_url)
            current_progress += 1
            print_progress(current_progress, total_parent_repos, message="Scanning repositories")
            if not tf_contents:
                if DEBUG:
                    print(f"[DEBUG] GitHub API failed for parent repo {org}/{repo}, falling back to git clone.")
                    if api_error:
                        print(f"[DEBUG] API error: {api_error}")
                if tmp_root:
                    os.makedirs(tmp_root, exist_ok=True)
                    temp_dir_context = tempfile.TemporaryDirectory(prefix=".", dir=tmp_root)
                else:
                    temp_dir_context = tempfile.TemporaryDirectory(prefix=".")
                with temp_dir_context as tmpdir:
                    try:
                        clone_repo(f"https://{ENTERPRISE_URL}/{org}", repo, tmpdir)
                    except Exception:
                        continue
                    tf_files = find_tf_files(tmpdir)
                    for tf_file in tf_files:
                        modules = parse_modules(tf_file)
                        for mod in modules:
                            module_usages.append({
                                'parent_org': org,
                                'parent_repo': repo,
                                'parent_module': mod['name'],
                                'source': mod['source'],
                                'version': mod['version']
                            })
            else:
                for file_name, tf_text in tf_contents:
                    try:
                        obj = hcl2.loads(tf_text)
                    except Exception:
                        continue
                    for block in obj.get("module", []):
                        for name, attrs in block.items():
                            source = attrs.get("source")
                            version = attrs.get("version")
                            module_usages.append({
                                'parent_org': org,
                                'parent_repo': repo,
                                'parent_module': name,
                                'source': source,
                                'version': version
                            })
    print_progress(total_parent_repos, total_parent_repos, message="Scanning repositories")  # Set to 100% when truly done
    # Print all module usages before deduplication and downloading module repos
    print("")
    print(color_text("\nCollected module usage from all repositories:", "yellow"))
    for usage in module_usages:
        print(f"  Parent: {usage['parent_org']}/{usage['parent_repo']} | Module: {usage['parent_module']} | Source: {usage['source']} | Version: {usage['version']}")

    # Step 2: Deduplicate modules, keep mapping of usages
    unique_modules = {}
    for usage in module_usages:
        source = usage['source']
        if source is None:
            continue
        if source.startswith("./") or source.startswith("../"):
            if DEBUG:
                print(f"[DEBUG] Skipping local module source: {source}")
            continue
        key = normalize_module_key(source, usage['version'])
        if key not in unique_modules:
            unique_modules[key] = []
        unique_modules[key].append(usage)

    # Print deduplicated module repo list before downloading
    print("\nUnique module repos to be processed (deduped by repo and ref/version):")
    for (repo_url, key_version), usages in unique_modules.items():
        print(f"  Repo: {repo_url} | Ref/Version: {key_version} | Used by:")
        for usage in usages:
            print(f"    - {usage['parent_org']}/{usage['parent_repo']} (module: {usage['parent_module']})")

    # Calculate total repos to process (parent + unique module repos)
    total_module_repos = len(unique_modules)
    total_repos_to_process = total_parent_repos + total_module_repos

    # Step 3: Download/process each unique module repo once and cache results
    module_results = {}
    current_progress = 0
    print("")
    print_progress(0, total_module_repos, message="Scanning module source repositories")
    for (source, version), usages in unique_modules.items():
        current_progress += 1
        print_progress(current_progress, total_module_repos, message="Scanning module source repositories")
        if not source:
            module_results[(source, version)] = []
            continue
        
        if DEBUG:
            print(f"\n[DEBUG] Processing module: {source} (version: {version})")
        
        api_success = False
        
        # Check if this is a registry module FIRST (only if version is not None)
        ns, name, provider, submodule = parse_registry_source(source) if source else (None, None, None, None)
        if ns and name and provider and version is not None:
            if DEBUG:
                print(f"[DEBUG] Registry module detected: {source}")
                if submodule:
                    print(f"[DEBUG] Submodule path: {submodule}")
            
            # Get the main module's GitHub URL
            registry_source_url = get_registry_module_source(ns, name, provider)
            if registry_source_url:
                if DEBUG:
                    print(f"[DEBUG] Resolved registry module to: {registry_source_url}")
                
                # Add submodule path if present
                if submodule:
                    registry_source_url = f"{registry_source_url}//{submodule}"
                    if DEBUG:
                        print(f"[DEBUG] Full URL with submodule: {registry_source_url}")
                
                if "github.com" in registry_source_url or (ENTERPRISE_URL and ENTERPRISE_URL in registry_source_url):
                    try:
                        constraints = scan_module_version_dependencies_api(registry_source_url, version)
                        # 0 constraints is a valid result - don't treat as failure
                        module_results[(source, version)] = constraints
                        api_success = True
                        if DEBUG:
                            print(f"[DEBUG] API scan completed successfully: found {len(constraints)} constraints")
                    except Exception as e:
                        if DEBUG:
                            print(f"[DEBUG] Failed to scan registry module {source}: {e}")

        # Handle None version (branch-based repos) or non-registry modules
        if not api_success:
            # Parse the source to extract repo URL and ref
            parsed_source = parse_private_source(source)
            repo_url, subdir, url_ref = parsed_source if parsed_source else (None, None, None)
            
            if not repo_url:
                # Not a private repo format, try as direct GitHub URL
                repo_url = source
                url_ref = None
                subdir = None
            
            if version is None:
                if DEBUG:
                    print(f"[DEBUG] No version specified - treating as branch-based repository")
                
                # For None version, use ref from URL or default branch
                if url_ref:
                    if DEBUG:
                        print(f"[DEBUG] Using ref from URL: {url_ref}")
                    target_ref = url_ref
                else:
                    if DEBUG:
                        print(f"[DEBUG] No ref in URL - will use default branch")
                    target_ref = None
                
                # Try API first for branch-based repos
                if "github.com" in repo_url or (ENTERPRISE_URL and ENTERPRISE_URL in repo_url):
                    try:
                        constraints = scan_module_version_dependencies_api(source, None)
                        # 0 constraints is a valid result - don't treat as failure
                        module_results[(source, version)] = constraints
                        api_success = True
                        if DEBUG:
                            print(f"[DEBUG] API scan completed successfully: found {len(constraints)} constraints")
                    except Exception as e:
                        if DEBUG:
                            print(f"[DEBUG] GitHub API failed for branch-based repo {source}: {e}")
                            
                # Fallback to git clone for branch-based repos
                if not api_success:
                    if DEBUG:
                        print(f"[DEBUG] Falling back to git clone for branch-based repo: {source}")
                    
                    # Ensure proper .git extension
                    clone_url = repo_url
                    if clone_url and not clone_url.endswith('.git'):
                        # Check if there's a submodule path (// after the repo name)
                        if '//' in clone_url:
                            # Split the URL to add .git only to the repo part
                            if '//github.com' not in clone_url and f'//{ENTERPRISE_URL}' not in clone_url:
                                # This is a submodule path, not the protocol
                                repo_part, submodule_part = clone_url.split('//', 1)
                                if ('github.com' in repo_part or (ENTERPRISE_URL and ENTERPRISE_URL in repo_part)):
                                    clone_url = f"{repo_part}.git//{submodule_part}"
                        else:
                            # No submodule path, safe to add .git
                            if ('github.com' in clone_url or (ENTERPRISE_URL and ENTERPRISE_URL in clone_url)):
                                clone_url += '.git'
                    
                    if ".git" in clone_url or "github.com" in clone_url or (ENTERPRISE_URL and ENTERPRISE_URL in clone_url):
                        if DEBUG:
                            print(f"[DEBUG] Cloning from: {clone_url}")
                        
                        # For None version, always use ref (branch) not version (tag)
                        module_results[(source, version)] = scan_private_module(clone_url, ref=target_ref, version=None)
                    else:
                        module_results[(source, version)] = []
            
            else:
                # Version is specified (semantic version or branch name)
                if DEBUG:
                    print(f"[DEBUG] Version specified: {version}")
                
                # Try GitHub API first for versioned modules
                if "github.com" in source or ENTERPRISE_URL and ENTERPRISE_URL in source:
                    try:
                        constraints = scan_module_version_dependencies_api(source, version)
                        # 0 constraints is a valid result - don't treat as failure
                        module_results[(source, version)] = constraints
                        api_success = True
                        if DEBUG:
                            print(f"[DEBUG] API scan completed successfully: found {len(constraints)} constraints")
                    except Exception as e:
                        if DEBUG:
                            print(f"[DEBUG] GitHub API failed for {source}: {e}")
                
                # Final fallback to git clone for versioned modules
                if not api_success:
                    if DEBUG:
                        print(f"[DEBUG] Falling back to git clone for {source} (version: {version})")
                    
                    # Use resolved registry URL if available, otherwise use original source
                    clone_url = registry_source_url if (ns and name and provider and registry_source_url) else source
                    
                    # Ensure proper .git extension
                    if clone_url and not clone_url.endswith('.git'):
                        # Check if there's a submodule path (// after the repo name)
                        if '//' in clone_url:
                            # Split the URL to add .git only to the repo part
                            if '//github.com' not in clone_url and f'//{ENTERPRISE_URL}' not in clone_url:
                                # This is a submodule path, not the protocol
                                repo_part, submodule_part = clone_url.split('//', 1)
                                if ('github.com' in repo_part or (ENTERPRISE_URL and ENTERPRISE_URL in repo_part)):
                                    clone_url = f"{repo_part}.git//{submodule_part}"
                        else:
                            # No submodule path, safe to add .git
                            if ('github.com' in clone_url or (ENTERPRISE_URL and ENTERPRISE_URL in clone_url)):
                                clone_url += '.git'

                    if ".git" in clone_url or "github.com" in clone_url or (ENTERPRISE_URL and ENTERPRISE_URL in clone_url):
                        if DEBUG:
                            print(f"[DEBUG] Cloning from: {clone_url}")
                        
                        # Determine if version is actually a ref/branch or a real version
                        is_semantic_version = version and re.match(r'^\d+\.\d+', version)
                        
                        if url_ref:
                            # URL has explicit ref - use as branch
                            module_results[(source, version)] = scan_private_module(clone_url, ref=url_ref, version=None)
                        elif is_semantic_version:
                            # Version looks like semantic version - use as tag
                            module_results[(source, version)] = scan_private_module(clone_url, ref=None, version=version)
                        else:
                            # Version doesn't look semantic - treat as branch
                            module_results[(source, version)] = scan_private_module(clone_url, ref=version, version=None)
                    else:
                        module_results[(source, version)] = []
                        
    print_progress(total_module_repos, total_module_repos, message="Scanning module source repositories")
    print("\n\nScan complete.\n")
    print(color_text(f"Completed module source repository scanning:", "yellow"))

    # Step 4: Associate results back to parent repos/modules
    scan_results = {}
    for (source, version), usages in unique_modules.items():
        constraints = module_results.get((source, version), [])
        for usage in usages:
            org = usage['parent_org']
            repo = usage['parent_repo']
            mod_name = usage['parent_module']
            if org not in scan_results:
                scan_results[org] = {}
            if repo not in scan_results[org]:
                scan_results[org][repo] = []
            scan_results[org][repo].append({
                "name": mod_name,
                "source": source,
                "version": version,
                "dependencies": constraints
            })

    # Print results at the end
    for org, repos in scan_results.items():
        print(f"\nOrganization: {org}")
        for repo, modules in repos.items():
            print(f"  Repository: {repo}")
            for mod in modules:
                if "error" in mod:
                    print(f"    Error: {mod['error']}")
                    continue
                print(f"    Module: {mod['name']}, Source: {mod['source']}, Version: {mod['version']}")
                for dep in mod.get("dependencies", []):
                    file_path = dep.get('file')
                    if file_path:
                        tempdir_match = re.match(r"(/var/folders/[^/]+/[^/]+/T/\.[^/]+)", file_path)
                        if tempdir_match:
                            file_path = file_path.replace(tempdir_match.group(1), "")
                        else:
                            file_path = re.sub(r".*T/\.[^/]+", "", file_path)
                    if "name" in dep:
                        print(f"      Dependency: {dep['name']}, Source: {dep.get('source')}, Version: {dep.get('version')}")
                    elif "required_version" in dep:
                        print(f"      Terraform Version Constraint: {dep.get('required_version')} (file: {file_path})")
                    elif "provider" in dep and "version" in dep:
                        print(f"      Provider Version Constraint: {dep.get('provider')} version {dep.get('version')} (file: {file_path})")
                    else:
                        print(f"      Other Dependency Info: {dep}")
    
    if DEBUG:
        print(f"\n[DEBUG] Repo cache statistics:")
        print(f"[DEBUG] Total repos cached: {len(repo_cache)}")
        for (repo_url, version), (tf_contents, api_error) in repo_cache.items():
            file_count = len(tf_contents) if tf_contents else 0
            print(f"[DEBUG]   {repo_url} (v{version}): {file_count} .tf files")
            
    if not target_terraform_version:
        # Summary block for highest version constraints
        print("")
        print("-------------------------------------------")
        print(" Result Summary: Version Constraints ")
        print("-------------------------------------------")
        print("")
        min_versions, max_versions = find_min_max_constraints(scan_results)
        if min_versions:
            highest_min = max(min_versions, key=lambda x: x[0])
            print(color_text(
                f"  Minimum Supported Terraform Version: {'.'.join(map(str, highest_min[0]))} \n   - Module: {highest_min[1]} \n   - Repo: {highest_min[2]} \n   - Org: {highest_min[3]} \n   - Constraint: {highest_min[4]}",
                "violet"
            ))
        else:
            print("  No minimum tf version constraints found.")
        if max_versions:
            lowest_max = min(max_versions, key=lambda x: x[0])
            print(color_text(
                f"  Maximum Supported Terraform Version: {'.'.join(map(str, lowest_max[0]))} \n   - Module: {lowest_max[1]} \n   - Repo: {lowest_max[2]} \n   - Org: {lowest_max[3]} \n   - Constraint: {lowest_max[4]}",
                "yellow"
            ))
        else:
            print("  No maximum tf version constraints found.")

        print(color_text(f"⚠️  No target Terraform version specified in repositories.yaml", "yellow"))
        print("Add 'terraform_version: \"1.x.x\"' to your YAML file to enable compatibility analysis.")

    else:
        print("")
        print("=" * 80)
        print(f"TERRAFORM VERSION COMPATIBILITY ANALYSIS")
        print(f" >>> Target Terraform Version: {target_terraform_version}")
        print("=" * 80)
        
        compatible_modules, incompatible_modules = analyze_terraform_compatibility(module_results, unique_modules, target_terraform_version)        
        
        if not incompatible_modules:
            print(color_text(f"\n✅ SUCCESS: Terraform {target_terraform_version} is compatible with all scanned modules!", "violet"))
        else:
            print(color_text(f"\n❌ INCOMPATIBILITY DETECTED: Terraform {target_terraform_version} is NOT compatible with some modules.", "yellow"))
            print(f"\nIncompatible modules ({len(incompatible_modules)}):")
            print("-" * 60)
            
            # Group by parent repo for better organization
            repo_issues = {}
            for module in incompatible_modules:
                source = module["source"]
                if source not in repo_issues:
                    repo_issues[source] = []
                repo_issues[source].append(module)
            
            for source, modules in repo_issues.items():
                print(f"\n📦 Module: {source}")
                for module in modules:
                    print(f"  ├─ Version: {module['version']}")
                    print(f"  ├─ Constraint: {module['constraint']}")
                    print(f"  ├─ File: {module['file']}")
                    print(f"  └─ Using:")
                    for usage in module['parent_usages']:
                        print(f"      • {usage['parent_org']}/{usage['parent_repo']} (module: {usage['parent_module']})")

if __name__ == "__main__":
    main()