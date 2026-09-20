# Sourced by every scenario. One job: refuse to run against anything that is not
# the lab.
#
# These scripts generate attack traffic so the IDS has something to detect. That is
# their whole purpose and it is only defensible in one place - the isolated lab
# bridge. A target outside 172.30.0.0/24 is either a mistake or a misuse, and either
# way the answer is to stop before a single packet leaves.

LAB_SUBNET_PREFIX="172.30.0."

require_lab_target() {
    # $1: the address a scenario is about to point a tool at.
    case "$1" in
        "${LAB_SUBNET_PREFIX}"*) : ;;
        *)
            echo "refusing to run against ${1}: scenarios target the lab only" \
                 "(${LAB_SUBNET_PREFIX}0/24)" >&2
            exit 2
            ;;
    esac
}

# The lab hosts, from infra/docker-compose.yml. Kept here so a scenario names a role
# rather than repeating an address.
VICTIM_WEB="172.30.0.10"
VICTIM_SSH="172.30.0.11"
