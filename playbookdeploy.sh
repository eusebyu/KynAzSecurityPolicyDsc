set -euxo pipefail
cleanup() {
    ARG=$?
    rm -rf $venvPath
    exit $ARG
}
trap cleanup EXIT
PROXY="http://nl-proxy-access.net.abnamro.com:8080"
# create temporary folder
venvPath=$(mktemp -d -t ansvenv_XXXXXX)
# create virtual environment
python3.8 -m venv $venvPath
# install ansible engine
source $venvPath/bin/activate
python3 -m pip install -U --proxy=$PROXY --no-cache-dir pip
python3 -m pip install --proxy=$PROXY --no-cache-dir ansible --log=/tmp/ans.log
# get playbooks
git clone https://github.com/eusebyu/pht-role-rhel8-cis.git $venvPath/github
# apply settings
ansible-playbook -i $venvPath/github/inventory $venvPath/github/playbook.yml