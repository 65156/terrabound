# Terrabound
Terrabound is a terraform version constraint sniffer, it will audit a list of your existing public Github or GHE github repositories, discovering terraform modules and then checking the module source code repositories for version constraints.

It will produce false positives if version constaints exist in any subfolders of the source module repositories as it simply uses pattern detection inside terraform blocks.

## Example Output
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

## Usage
### Prepare Virtual Environment
```
python -m venv .venv
source .venv/bin/activate
```

### Set Environment Variables
You need to set GITHUB_TOKEN if you want to scan public Github repositories and GITHUB_TOKEN_ENTERPRISE & ENTERPRISE_URL if scanning any repositories on GHE.

```
export GITHUB_TOKEN=xxxxxxxx
export GITHUB_TOKEN_ENTERPRISE=xxxxxxx
export ENTERPRISE_URL=github.contoso.com
```

### Install pre-requisites
pip install -r requirements.

### Prepare Yaml
Configure repositories.yaml file for processing-

Supports
- regex pattern filtering.
- list filtering (matches exact string)
- team filtering

#### Example 
```
terraform_version: 1.10.5
repositories:
  - org: https://github.contoso.com/organisation01/
    team: foxtrot-3 # github enterprise team name
    pattern: '^repository-.*$' # will select all repositories for that team that match the pattern.
  - org: https://github.contoso.com/organisation02
    list: 
      - repository-dsi31x # repository names
      - repository-dja012
      - repository-ds19fc
```

### Run
python run.py

#### Optional - Debugging
python run.py --debug
