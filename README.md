# Terrabound
Terrabound is a terraform version constraint sniffer, it will audit a list of your existing public Github or GHE github repositories, discovering terraform modules and then checking the module source code repositories for version constraints.

It will produce false positives if version constaints exist in any subfolders of the source module repositories as it simply uses pattern detection inside terraform blocks.

## Example output

Failure
```
================================================================================
TERRAFORM VERSION COMPATIBILITY ANALYSIS
 >>> Target Terraform Version: 1.10.5
================================================================================

❌ INCOMPATIBILITY DETECTED: Terraform 1.10.5 is NOT compatible with some modules.

Incompatible modules (3):
------------------------------------------------------------

📦 Module: terraform-ibm-modules/security-group/ibm
  ├─ Version: 2.4.0
  ├─ Constraint: >= 1.3, <1.6.0
  ├─ File: /versions.tf
  └─ Using:
      • organisation01/repository-kd19sx (module: sg)

📦 Module: terraform-ibm-modules/base-ocp-vpc/ibm
  ├─ Version: 3.18.3
  ├─ Constraint: >= 1.3.0, < 1.7.0
  ├─ File: /modules/fscloud/version.tf
  └─ Using:
      • organisation01/repository-kd19sx (module: roks)
  ├─ Version: 3.18.3
  ├─ Constraint: >= 1.3.0, < 1.7.0
  ├─ File: /version.tf
  └─ Using:
      • organisation02/repository-ds19fc (module: roks)
```

Success
```
================================================================================
TERRAFORM VERSION COMPATIBILITY ANALYSIS
 >>> Target Terraform Version: 1.10.5
================================================================================

✅ SUCCESS: Terraform 1.10.5 is compatible with all scanned modules!
```

## Usage
### Prepare Python virtual environment
```
python -m venv .venv
source .venv/bin/activate
```

### Set environment variables
You need to set GITHUB_TOKEN if you want to scan public Github repositories and GITHUB_TOKEN_ENTERPRISE & ENTERPRISE_URL if scanning any repositories on GHE.

```
export GITHUB_TOKEN=xxxxxxxx
export GITHUB_TOKEN_ENTERPRISE=xxxxxxx
export ENTERPRISE_URL=github.contoso.com
```

### Install pre-requisites
`pip install -r requirements.`

### Prepare repositories list (YAML)
Configure repositories.yaml file for processing-

Supports
- regex pattern filtering.
- list filtering (matches exact string)
- team filtering

#### Examples
```
terraform_version: 1.10.5
repositories:
  # Scan repositories matching a pattern in a GHE environment
  - org: https://github.contoso.com/organisation01/
    team: foxtrot-3 # github enterprise team name
    pattern: '^repository-.*$' # will select all repositories for that team that match the pattern.
  # Scan specific repositories in a GHE Environment
  - org: https://github.contoso.com/organisation02
    list: 
      - repository-dsi31x # repository names
      - repository-dja012
      - repository-ds19fc
  # Scan specific repositories in a public GitHub organization
  - org: "https://github.com/terraform-aws-modules"
    list:
      - "terraform-aws-vpc"
      - "terraform-aws-eks"
      - "terraform-aws-rds"
  # Scan repositories matching a pattern
  - org: "https://github.com/hashicorp"
    pattern: "^terraform-provider-.*$"
  # Scan repositories from a specific GitHub team
  - org: "https://github.com/gruntwork-io"
    team: "core"  # Only works with GitHub token that has team access
```

### Run Terrabound
```
# Typical execution
python run.py

# Enable debugging output
python run.py --debug

# Specify custom temp folder 
python run.py --folder /path/to/temp/dir
```

