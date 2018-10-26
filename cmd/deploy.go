package cmd

import (
	bosherr "github.com/cloudfoundry/bosh-utils/errors"

	boshdir "github.com/cloudfoundry/bosh-cli/director"
	boshtpl "github.com/cloudfoundry/bosh-cli/director/template"
	boshui "github.com/cloudfoundry/bosh-cli/ui"
)

type DeployCmd struct {
	ui              boshui.UI
	deployment      boshdir.Deployment
	releaseUploader ReleaseUploader
	ccs             CertificateConfigurationServer
}

type ReleaseUploader interface {
	UploadReleases([]byte) ([]byte, error)
}

type CertificateConfigurationServer interface {
	// PrepareForNewDeploy is expected to:
	// 1. Delete any certificates that are not CAs, they are always safe to regenerate.
	// 2. For any certificates that are CAs, and only one active, create new, make it active, mark old as transitional.
	// 3. Return a map of variables (such as foo_ca.certificate) that contains all the old CAs that are still in transitional state.
	PrepareForNewDeploy() (map[string]string, error)

	// PostSuccessfulDeploy is expected to:
	// 1. Delete any certificates that are not CAs, they are always safe to regenerate.
	// 2. For any certificates that are CAs, mark the transitional ones as not current.
	PostSuccessfulDeploy() error
}

func NewDeployCmd(
	ui boshui.UI,
	deployment boshdir.Deployment,
	releaseUploader ReleaseUploader,
	ccs CertificateConfigurationServer,
) DeployCmd {
	return DeployCmd{ui, deployment, releaseUploader, ccs}
}

func (c DeployCmd) Run(opts DeployOpts) error {
	tpl := boshtpl.NewTemplate(opts.Args.Manifest.Bytes)

	var additionalVals map[string]string
	if opts.ProgressiveCertRotation {
		var err error
		additionalVals, err = c.ccs.PrepareForNewDeploy()
		if err != nil {
			return err
		}
	}

	bytes, err := tpl.EvaluateWithAdditional(opts.VarFlags.AsVariables(), opts.OpsFlags.AsOp(), boshtpl.EvaluateOpts{}, additionalVals)
	if err != nil {
		return bosherr.WrapErrorf(err, "Evaluating manifest")
	}

	err = c.checkDeploymentName(bytes)
	if err != nil {
		return err
	}

	bytes, err = c.releaseUploader.UploadReleases(bytes)
	if err != nil {
		return err
	}

	deploymentDiff, err := c.deployment.Diff(bytes, opts.NoRedact)
	if err != nil {
		return err
	}

	diff := NewDiff(deploymentDiff.Diff)
	diff.Print(c.ui)

	err = c.ui.AskForConfirmation()
	if err != nil {
		return err
	}

	updateOpts := boshdir.UpdateOpts{
		RecreatePersistentDisks: opts.RecreatePersistentDisks,
		Recreate:                opts.Recreate,
		Fix:                     opts.Fix,
		SkipDrain:               opts.SkipDrain,
		DryRun:                  opts.DryRun,
		Canaries:                opts.Canaries,
		MaxInFlight:             opts.MaxInFlight,
		Diff:                    deploymentDiff,
	}

	err = c.deployment.Update(bytes, updateOpts)
	if err != nil {
		return err
	}

	if opts.ProgressiveCertRotation {
		err = c.ccs.PostSuccessfulDeploy()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c DeployCmd) checkDeploymentName(bytes []byte) error {
	manifest, err := boshdir.NewManifestFromBytes(bytes)
	if err != nil {
		return bosherr.WrapErrorf(err, "Parsing manifest")
	}

	if manifest.Name != c.deployment.Name() {
		errMsg := "Expected manifest to specify deployment name '%s' but was '%s'"
		return bosherr.Errorf(errMsg, c.deployment.Name(), manifest.Name)
	}

	return nil
}
