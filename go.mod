module github.com/kubernetes-csi/csi-driver-image-populator

go 1.15

require (
	github.com/container-storage-interface/spec v1.0.0
	github.com/docker/docker v20.10.17+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/kubernetes-csi/drivers v1.0.0
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/spf13/afero v1.5.1 // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	google.golang.org/grpc v1.36.1
	gotest.tools/v3 v3.2.0 // indirect
	k8s.io/api v0.24.2
	k8s.io/apimachinery v0.24.2
	k8s.io/client-go v0.24.2
	k8s.io/kubernetes v1.12.2
	sigs.k8s.io/yaml v1.3.0 // indirect
)
