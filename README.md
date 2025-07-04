# container-and-kubernetes-security

## Container?

Isolation in the same system with unique namespaces.

- PID - Isolation of process ids
- User - Isolation of users & UIDs
- Mount - Isolation of mount points
- Net - Isolation of networking interfaces & environment
- UTS - Isolation of hostname
- IPC - Isolation of IPC traffic
- Cgroup - Isolation of cgroups (memory & cpu)

https://github.com/rewanthtammana/containers-from-scratch/blob/master/main.go#L32

```bash
docker run --rm -it ubuntu bash
# sleep 1d
```
```bash
ps -ef | grep sleep 1d
ls /proc/<PID>/ns
```
You can see the docker container namespaces! In real all the data, processes, etc are existing on the host machine.
```bash
docker run --name debugcontainer --rm -it ubuntu bash
# echo "inside container" > file.txt
```
```bash
docker inspect debugcontainer | grep -i upperdir
```
In docker inspect, you will see the below fields.

LowerDir: contains the files of the base system UpperDir: all changes to the base system are stored in upperDir
```bash
docker inspect debugcontainer | grep -i upperdir
cat <upperdir>/file.txt
```
Viola! The file you created inside the container is accessible from the host machine.

What does it mean to be root inside a container?

You can run these on killercoda!

Root on host machine & root inside container
```bash
$ docker run --rm -it nginx bash
# sleep 1d
```
```bash
$ ps -ef | grep sleep
```
Non-root on host machine & root inside container
```bash
$ adduser ubuntu
$ sudo chown ubuntu:ubuntu /var/run/docker.sock
$ su - ubuntu
$ docker run --rm -it nginx bash
# sleep 2d
$ ps -ef | grep sleep
```
Root on host machine & non-root inside container
```bash
$ docker run --rm --user 1000:1000 -it nginx bash
# sleep 3d
```
```bash
$ ps -ef | grep sleep
```
Since docker daemon runs as root, eventually all the processes triggered by it run as root. Another example -
```bash
echo "I'm root" >> /tmp/groot.txt
chmod 0600 /tmp/groot.txt
su - ubuntu
cat /tmp/groot.txt
```
```bash
docker run --rm -it -v /tmp/groot.txt:/tmp/groot.txt nginx cat /tmp/groot.txt
docker run --rm -it -u 1000:1000 -v /tmp/groot.txt:/tmp/groot.txt nginx cat /tmp/groot.txt
```
When the user inside the container is non-root, even if the container gets compromised, the attacker cannot read the mounted sensitive files unless they have the appropriate permissions or escalate the privileges.

### Privileged container
Kernel files are crucial on host machine, let's see if we can mess with that.

https://github.com/torvalds/linux/blob/v5.0/Documentation/sysctl/vm.txt#L809
```bash
$ cat /proc/sys/vm/swappiness
$ docker run --rm --privileged -it ubuntu bash
# cat /proc/sys/vm/swappiness
60
# echo 10 > /proc/sys/vm/swappiness
$ cat /proc/sys/vm/swappiness
```
These kind of changes to the kernel files can create DoS attacks!

Let's say you got access to one of the containers by exploiting an application or some other means. How will you identify if you are inside a privileged or normal container? There are many ways! A few of them are!

Run two containers, one normal & one privileged
```bash
docker run --rm -it ubuntu bash
docker run --rm --privileged -it ubuntu bash
```
Check for mount permissions & masking
```bash
mount | grep 'ro,'
mount | grep /proc.*tmpfs
```
Linux capabilities - we will see more about it in the next section!
```bash
capsh --print
```
Seccomp - Limit the syscalls
```bash
grep Seccomp /proc/1/status
```
Capabilities

https://command-not-found.com/capsh https://man7.org/linux/man-pages/man7/capabilities.7.html https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/
```bash
capsh --print
```
```bash
grep Cap /proc/self/status
capsh --decode=<decodeBnd>
```
Demonstrating that the processes inside the container inherits it's capabilities
```bash
$ docker run --rm -it ubuntu sleep 1d &
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
```
```bash
$ docker run --rm --privileged -it ubuntu sleep 2d &
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
```
```bash
$ docker run --rm --cap-drop=all -it ubuntu sleep 3d &
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
```
CapEff: The effective capability set represents all capabilities the process is using at the moment.

CapPrm: The permitted set includes all capabilities a process may use.

CapInh: Using the inherited set all capabilities that are allowed to be inherited from a parent process can be specified.

CapBnd: With the bounding set its possible to restrict the capabilities a process may ever receive.

CapAmb: The ambient capability set applies to all non-SUID binaries without file capabilities.

About a few capabilities:

CAP_CHOWN - allows the root use to make arbitrary changes to file UIDs and GIDs

CAP_DAC_OVERRIDE - allows the root user to bypass kernel permission checks on file read, write and execute operations.

CAP_SYS_ADMIN - Most powerful capability. It allows to manage cgroups of the system, thereby allowing you to control system resources
```bash
docker run --rm -it busybox:1.28 ping google.com
```
```bash
docker run --rm --cap-drop=NET_RAW -it busybox:1.28 ping google.com
```
```bash
docker run --rm -it --cap-drop=all ubuntu chown nobody /tmp
docker run --rm -it ubuntu chown nobody /tmp
docker run --rm -it --cap-drop=all --cap-add=chown ubuntu chown nobody /tmp
```
https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/

https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd

### Trivy - Scan docker images
https://github.com/aquasecurity/trivy

Visit the latest releases section & install the binary!
```bash
trivy i nginx
```
Since, you have learnt argocd. I will teach you how to fix issues in argocd!

This will not work on killercoda due to disk space constraints, use your local machine to try it!
```bash
git clone https://github.com/argoproj/argo-cd
cd argo-cd
# Errors due to BUILDPLATFORM specification, just remove it from the Dockerfile!
docker build . -t argocd
trivy i argocd
```
It will take sometime to build, so let's review multi-stage builds for a while.

https://github.com/argoproj/argo-cd/blob/master/Dockerfile

Change the base image in the dockerfile, rebuild the argocd image & then scan it. Most of the issues will be sorted out!

https://docs.docker.com/develop/develop-images/multistage-build/
```bash

trivy i ubuntu:22.04
trivy i ubuntu:21.10
trivy i ubuntu:21.04
```
Distroless images

https://github.com/GoogleContainerTools/distroless
```bash
trivy i gcr.io/distroless/static-debian11
```
```bash
docker run --rm -it gcr.io/distroless/static-debian11 sh
docker run --rm -it gcr.io/distroless/static-debian11 ls
docker run --rm -it gcr.io/distroless/static-debian11 id
docker run --rm -it gcr.io/distroless/static-debian11 whoami
```
Analyzing docker images
```bash
docker pull ubuntu
docker inspect ubuntu
```
But the above inspect command will not help you to examine the layers of the docker images

### DoSing the container - Fork bomb
DO NOT RUN IN ON YOUR COMPUTER EVER. RUN IN KILLERCODA ONLY
```bash
:(){ :|:& };:
```
We will do this on killercoda! Get ready to crash your system.
```bash
docker run --name unlimited --rm -it ubuntu bash
docker stats unlimited
```
```bash
docker run --name withlimits --rm -m 0.5Gi --cpus 0.8 -it ubuntu bash
docker stats withlimits
```
### Dockle
https://github.com/goodwithtech/dockle

Installation
```bash
VERSION=$(
 curl --silent "https://api.github.com/repos/goodwithtech/dockle/releases/latest" | \
 grep '"tag_name":' | \
 sed -E 's/.*"v([^"]+)".*/\1/' \
) && curl -L -o dockle.deb https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.deb
sudo dpkg -i dockle.deb && rm dockle.deb
```
```bash
dockle madhuakula/k8s-goat-users-repo
```
### Runtime security
Falco

https://github.com/falcosecurity/falco

You can try on Killercoda!
```bash
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y
apt-get -y install linux-headers-$(uname -r)
apt-get install -y falco
falco
```
```bash
docker run --name nginx --rm -it -d nginx
```
```bash
docker exec -it nginx bash
cat /etc/shadow
```
https://github.com/developer-guy/awesome-falco

### NIST framework for containers
https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf

## Kubernetes
### Network Policies

https://github.com/ahmetb/kubernetes-network-policy-recipes

Show your presentation on compromising organizational security bug! A detailed presentation on million dollar company hack!

If the database connection to the end-user is blocked, then the attack would have never happened.

### Kyverno
Demonstrate on how you can control the deployment configuration

Install Kyverno,
```bash
kubectl create -f https://raw.githubusercontent.com/kyverno/kyverno/main/config/install.yaml
```
```bash
echo '''apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-app-label
spec:
  validationFailureAction: enforce
  rules:
  - name: check-for-app-label
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "label `app` is required"
      pattern:
        metadata:
          labels:
            app: "?*"''' > check-labels.yaml
```
```bash
kubectl apply -f check-labels.yaml
```
```bash
kubectl run nginx --image nginx
kubectl run nginx --image nginx --labels rand=wer
kubectl run nginx --image nginx --labels app=wer
```
### Kubescape
https://github.com/armosec/kubescape
```bash
wget https://github.com/armosec/kubescape/releases/download/v2.0.164/kubescape-ubuntu-latest
chmod +x kubescape-ubuntu-latest
sudo mv kubescape-ubuntu-latest /usr/local/bin/kubescape
```
To gain best results, we can install the vulnerable cluster, kubernetes-goat on killercoda & then trigger the scan.
```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
bash setup-kubernetes-goat.sh
bash access-kubernetes-goat.sh
```
```bash
kubescape scan
kubescape scan framework nsa
kubescape scan framework nsa -v
kubescape scan framework nsa -v --exclude-namespaces kube-system
```
```bash
kubectl edit deploy system-monitor-deployment
```
## More
There are more things like apparmor, selinux, mutating webhooks, seccomp, service mesh, observability, tracing, & lot more that help to harden a container/Kubernetes environment.

Further practice on container internals & security - https://contained.af/
