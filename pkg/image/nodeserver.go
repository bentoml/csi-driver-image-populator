/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package image

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/credentialprovider"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/kubernetes/pkg/util/mount"

	"github.com/kubernetes-csi/drivers/pkg/csi-common"
)

const (
	deviceID = "deviceID"
)

var (
	TimeoutError = fmt.Errorf("Timeout")
)

type nodeServer struct {
	*csicommon.DefaultNodeServer
	Timeout  time.Duration
	execPath string
	args     []string
}

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {

	// Check arguments
	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "Volume capability missing in request")
	}
	if len(req.GetVolumeId()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}
	if len(req.GetTargetPath()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path missing in request")
	}

	volumeContext := req.GetVolumeContext()
	image := volumeContext["image"]

	err := ns.setupVolume(ctx, req.GetVolumeId(), image, volumeContext)
	if err != nil {
		return nil, err
	}

	targetPath := req.GetTargetPath()
	notMnt, err := mount.New("").IsLikelyNotMountPoint(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(targetPath, 0750); err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			notMnt = true
		} else {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	if !notMnt {
		return &csi.NodePublishVolumeResponse{}, nil
	}

	fsType := req.GetVolumeCapability().GetMount().GetFsType()

	deviceId := ""
	if req.GetPublishContext() != nil {
		deviceId = req.GetPublishContext()[deviceID]
	}

	readOnly := req.GetReadonly()
	volumeId := req.GetVolumeId()
	attrib := req.GetVolumeContext()
	mountFlags := req.GetVolumeCapability().GetMount().GetMountFlags()

	glog.V(4).Infof("target %v\nfstype %v\ndevice %v\nreadonly %v\nvolumeId %v\nattributes %v\n mountflags %v\n",
		targetPath, fsType, deviceId, readOnly, volumeId, attrib, mountFlags)

	options := []string{"bind"}
	if readOnly {
		options = append(options, "ro")
	}

	args := []string{"mount", volumeId}
	ns.execPath = "/bin/buildah" // FIXME
	output, err := ns.runCmd(args)
	// FIXME handle failure.
	provisionRoot := strings.TrimSpace(string(output[:]))
	glog.V(4).Infof("container mount point at %s\n", provisionRoot)

	mounter := mount.New("")
	path := provisionRoot
	if err := mounter.Mount(path, targetPath, "", options); err != nil {
		return nil, err
	}

	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {

	// Check arguments
	if len(req.GetVolumeId()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}
	if len(req.GetTargetPath()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path missing in request")
	}
	targetPath := req.GetTargetPath()
	volumeId := req.GetVolumeId()

	// Unmounting the image
	err := mount.New("").Unmount(req.GetTargetPath())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	glog.V(4).Infof("image: volume %s/%s has been unmounted.", targetPath, volumeId)

	err = ns.unsetupVolume(volumeId)
	if err != nil {
		return nil, err
	}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func parseDockerConfigFromSecretData(data map[string][]byte) (credentialprovider.DockerConfig, error) {
	if dockerConfigJSONBytes, existed := data[corev1.DockerConfigJsonKey]; existed {
		if len(dockerConfigJSONBytes) > 0 {
			dockerConfigJSON := credentialprovider.DockerConfigJson{}
			if err := json.Unmarshal(dockerConfigJSONBytes, &dockerConfigJSON); err != nil {
				return nil, err
			}

			return dockerConfigJSON.Auths, nil
		}
	}

	if dockercfgBytes, existed := data[corev1.DockerConfigKey]; existed {
		if len(dockercfgBytes) > 0 {
			dockercfg := credentialprovider.DockerConfig{}
			if err := json.Unmarshal(dockercfgBytes, &dockercfg); err != nil {
				return nil, err
			}
			return dockercfg, nil
		}
	}

	return nil, nil
}

func (ns *nodeServer) setupVolume(ctx context.Context, volumeId string, image string, volumeContext map[string]string) error {
	tlsVerify := volumeContext["tlsVerify"] != "false"

	args := []string{"from", fmt.Sprintf("--tls-verify=%v", tlsVerify), "--name", volumeId, "--pull"}
	secretName := volumeContext["secret"]
	secretNamespace := volumeContext["secretNamespace"]
	if secretName != "" && secretNamespace != "" {
		config, err := rest.InClusterConfig()
		if err != nil {
			glog.Errorf("Failed to get kube config: %v", err)
			return err
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			glog.Errorf("Failed to get kube client: %v", err)
			return err
		}
		secret, err := clientset.CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			glog.Errorf("Failed to get secret %s/%s: %v", secretNamespace, secretName, err)
			return err
		}
		cred, err := parseDockerConfigFromSecretData(secret.Data)
		if err != nil {
			glog.Errorf("Failed to parse secret %s/%s: %v", secretNamespace, secretName, err)
			return err
		}
		basicKeyring := &credentialprovider.BasicDockerKeyring{}
		basicKeyring.Add(cred)
		dockerKeyring := credentialprovider.UnionDockerKeyring{basicKeyring}
		creds, withCredentials := dockerKeyring.Lookup(image)
		if withCredentials && len(creds) > 0 {
			args = append(args, "--creds", fmt.Sprintf("%s:%s", creds[0].Username, creds[0].Password))
		}
	}
	args = append(args, image)
	ns.execPath = "/bin/buildah" // FIXME
	output, err := ns.runCmd(args)
	// FIXME handle failure.
	// FIXME handle already deleted.
	provisionRoot := strings.TrimSpace(string(output[:]))
	// FIXME remove
	glog.V(4).Infof("container mount point at %s\n", provisionRoot)
	return err
}

func (ns *nodeServer) unsetupVolume(volumeId string) error {

	args := []string{"delete", volumeId}
	ns.execPath = "/bin/buildah" // FIXME
	output, err := ns.runCmd(args)
	// FIXME handle failure.
	// FIXME handle already deleted.
	provisionRoot := strings.TrimSpace(string(output[:]))
	// FIXME remove
	glog.V(4).Infof("container mount point at %s\n", provisionRoot)
	return err
}

func (ns *nodeServer) runCmd(args []string) ([]byte, error) {
	execPath := ns.execPath

	cmd := exec.Command(execPath, args...)

	timeout := false
	if ns.Timeout > 0 {
		timer := time.AfterFunc(ns.Timeout, func() {
			timeout = true
			// TODO: cmd.Stop()
		})
		defer timer.Stop()
	}

	output, execErr := cmd.CombinedOutput()
	if execErr != nil {
		if timeout {
			return nil, TimeoutError
		}
	}
	return output, execErr
}

func (ns *nodeServer) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *nodeServer) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return &csi.NodeStageVolumeResponse{}, nil
}
