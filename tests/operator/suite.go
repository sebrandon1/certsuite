// Copyright (C) 2020-2024 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package operator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/redhat-best-practices-for-k8s/certsuite/tests/common"
	"github.com/redhat-best-practices-for-k8s/certsuite/tests/identifiers"
	"github.com/redhat-best-practices-for-k8s/certsuite/tests/operator/access"
	"github.com/redhat-best-practices-for-k8s/certsuite/tests/operator/catalogsource"
	"github.com/redhat-best-practices-for-k8s/certsuite/tests/operator/openapi"
	"github.com/redhat-best-practices-for-k8s/certsuite/tests/operator/phasecheck"

	"github.com/redhat-best-practices-for-k8s/certsuite/internal/log"
	"github.com/redhat-best-practices-for-k8s/certsuite/pkg/checksdb"
	"github.com/redhat-best-practices-for-k8s/certsuite/pkg/provider"
	"github.com/redhat-best-practices-for-k8s/certsuite/pkg/stringhelper"
	"github.com/redhat-best-practices-for-k8s/certsuite/pkg/testhelper"
	"github.com/redhat-best-practices-for-k8s/certsuite/pkg/versions"
)

var (
	env provider.TestEnvironment

	beforeEachFn = func(check *checksdb.Check) error {
		env = provider.GetTestEnvironment()
		return nil
	}
)

//nolint:funlen
func LoadChecks() {
	log.Debug("Loading %s suite checks", common.OperatorTestKey)

	checksGroup := checksdb.NewChecksGroup(common.OperatorTestKey).
		WithBeforeEachFn(beforeEachFn)

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorInstallStatusSucceededIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorInstallationPhaseSucceeded(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorNoSCCAccess)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorInstallationAccessToSCC(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorIsInstalledViaOLMIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorOlmSubscription(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorHasSemanticVersioningIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorSemanticVersioning(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorCrdVersioningIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorCrdsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorCrdVersioning(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorCrdSchemaIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorCrdsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorCrdOpenAPISpec(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorSingleCrdOwnerIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorSingleCrdOwner(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorPodsNoHugepages)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env), testhelper.GetNoOperatorPodsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorPodsNoHugepages(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorOlmSkipRange)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorOlmSkipRange(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestMultipleSameOperatorsIdentifier)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testMultipleSameOperators(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestOperatorCatalogSourceBundleCountIdentifier)).
		WithSkipCheckFn(testhelper.GetNoCatalogSourcesSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOperatorCatalogSourceBundleCount(c, &env)
			return nil
		}))

	checksGroup.Add(checksdb.NewCheck(identifiers.GetTestIDAndLabels(identifiers.TestSingleOrMultiNamespacedOperatorInstallationInTenantNamespace)).
		WithSkipCheckFn(testhelper.GetNoOperatorsSkipFn(&env)).
		WithCheckFn(func(c *checksdb.Check) error {
			testOnlySingleOrMultiNamespacedOperatorsAllowedInTenantNamespaces(c, &env)
			return nil
		}))
}

// This function checks if single/multi namespaced operators should only be installed in the tenant dedicated operator namespace
func testOnlySingleOrMultiNamespacedOperatorsAllowedInTenantNamespaces(check *checksdb.Check, env *provider.TestEnvironment) {
	check.LogInfo("Starting testOnlySingleNamespacedOperatorsAllowedInTenantNamespaces")

	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	operatorNamespaces := make(map[string]bool)
	for _, operator := range env.Operators {
		operatorNamespace := operator.Csv.Annotations["olm.operatorNamespace"]
		for _, namespace := range env.Namespaces {
			if namespace == operatorNamespace {
				operatorNamespaces[operatorNamespace] = true
			}
		}
	}

	for operatorNamespace := range operatorNamespaces { // operator installed namespace
		check.LogInfo("Checking if namespace %s contains only valid single/ multi namespaced operators", operatorNamespace)

		isDedicatedOperatorNamespace, singleOrMultiNamespaceOperators, nonSingleOrMultiNamespaceOperators,
			csvsTargetingNamespace, operatorsFoundButNotUnderTest, podsNotBelongingToOperators, err := checkValidOperatorInstallation(operatorNamespace)

		check.LogInfo("isDedicatedOperatorNamespace=%t, singleOrMultiNamespaceOperators=%s, nonSingleOrMultiNamespaceOperators=%s, csvsTargetingNamespace=%s, operatorsFoundButNotUnderTest=%s, podsNotBelongingToOperators=%s", isDedicatedOperatorNamespace, singleOrMultiNamespaceOperators, nonSingleOrMultiNamespaceOperators, csvsTargetingNamespace, operatorsFoundButNotUnderTest, podsNotBelongingToOperators) //nolint:lll

		if err != nil {
			msg := fmt.Sprintf("Operator namespace %s check got error %v", operatorNamespace, err)
			check.LogError("%s", msg)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewNamespacedReportObject(msg, testhelper.Namespace, false, operatorNamespace))
			continue
		}

		if isDedicatedOperatorNamespace {
			var msg string
			if len(singleOrMultiNamespaceOperators) == 0 {
				msg = "Namespace contains no installed single/multi namespace operators"
			} else {
				msg = fmt.Sprintf("Namespace is dedicated to single/multi namespace operators (%s) ", strings.Join(singleOrMultiNamespaceOperators, ", "))
			}

			compliantObjects = append(compliantObjects, testhelper.NewNamespacedReportObject(msg, testhelper.Namespace, true, operatorNamespace))
		} else {
			msg := "Operator namespace is not dedicated to single/multi operators because "

			if len(nonSingleOrMultiNamespaceOperators) != 0 {
				msg += "- operators are installed with an install mode different from single/multi (" + strings.Join(nonSingleOrMultiNamespaceOperators, ", ") + ")\n"
			}

			if len(csvsTargetingNamespace) != 0 {
				msg += "- this namespace is the target namespace of other operators (" + strings.Join(csvsTargetingNamespace, ", ") + ")\n"
			}
			if len(operatorsFoundButNotUnderTest) != 0 {
				msg += "- operators not under test found (" + strings.Join(operatorsFoundButNotUnderTest, ", ") + ")\n"
			}
			if len(podsNotBelongingToOperators) != 0 {
				msg += "- invalid non operator pods found (" + strings.Join(podsNotBelongingToOperators, ", ") + ")"
			}

			nonCompliantNs := testhelper.NewNamespacedReportObject(msg, testhelper.Namespace, false, operatorNamespace)

			nonCompliantObjects = append(nonCompliantObjects, nonCompliantNs)
		}
		check.SetResult(compliantObjects, nonCompliantObjects)
	}
}

// This function check if the Operator CRD version follows K8s versioning
func testOperatorCrdVersioning(check *checksdb.Check, env *provider.TestEnvironment) {
	check.LogInfo("Starting testOperatorCrdVersioning")
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	for _, crd := range env.Crds {
		doesUseK8sVersioning := true
		nonCompliantVersion := ""

		for _, crdVersion := range crd.Spec.Versions {
			versionName := crdVersion.Name
			check.LogDebug("Checking for Operator CRD %s with version %s", crd.Name, versionName)

			if !versions.IsValidK8sVersion(versionName) {
				doesUseK8sVersioning = false
				nonCompliantVersion = versionName
				break
			}
		}

		if doesUseK8sVersioning {
			check.LogInfo("Operator CRD %s has valid K8s versioning ", crd.Name)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(crd.Namespace, crd.Name,
				"Operator CRD has valid K8s versioning ", true).AddField(testhelper.CrdVersion, crd.Name))
		} else {
			check.LogError("Operator CRD %s has invalid K8s versioning %s ", crd.Name, nonCompliantVersion)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(crd.Namespace, crd.Name,
				"Operator CRD has invalid K8s versioning ", false).AddField(testhelper.CrdVersion, crd.Name))
		}
	}
	check.SetResult(compliantObjects, nonCompliantObjects)
}

// This function checks if the operator CRD is defined with OpenAPI 3 specification
func testOperatorCrdOpenAPISpec(check *checksdb.Check, env *provider.TestEnvironment) {
	check.LogInfo("Starting testOperatorCrdOpenAPISpec")
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	for _, crd := range env.Crds {
		if openapi.IsCRDDefinedWithOpenAPI3Schema(crd) {
			check.LogInfo("Operator CRD %s is defined with OpenAPIV3 schema ", crd.Name)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(crd.Namespace, crd.Name,
				"Operator CRD is defined with OpenAPIV3 schema ", true).AddField(testhelper.OpenAPIV3Schema, crd.Name))
		} else {
			check.LogInfo("Operator CRD %s is not defined with OpenAPIV3 schema ", crd.Name)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(crd.Namespace, crd.Name,
				"Operator CRD is not defined with OpenAPIV3 schema ", false).AddField(testhelper.OpenAPIV3Schema, crd.Name))
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

// This function checks for semantic versioning of the installed operators
func testOperatorSemanticVersioning(check *checksdb.Check, env *provider.TestEnvironment) {
	check.LogInfo("Starting testOperatorSemanticVersioning")
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	for _, operator := range env.Operators {
		operatorVersion := operator.Version
		check.LogInfo("Testing Operator %q for version %s", operator, operatorVersion)

		if versions.IsValidSemanticVersion(operatorVersion) {
			check.LogInfo("Operator %q has a valid semantic version %s", operator, operatorVersion)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(operator.Namespace, operator.Name,
				"Operator has a valid semantic version ", true).AddField(testhelper.Version, operatorVersion))
		} else {
			check.LogError("Operator %q has an invalid semantic version %s", operator, operatorVersion)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(operator.Namespace, operator.Name,
				"Operator has an invalid semantic version ", false).AddField(testhelper.Version, operatorVersion))
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

func testOperatorInstallationPhaseSucceeded(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject
	for _, op := range env.Operators {
		check.LogInfo("Testing Operator %q", op)
		if phasecheck.WaitOperatorReady(op.Csv) {
			check.LogInfo("Operator %q is in Succeeded phase", op)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(op.Namespace, op.Name,
				"Operator on Succeeded state ", true).AddField(testhelper.OperatorPhase, string(op.Csv.Status.Phase)))
		} else {
			check.LogError("Operator %q is not in Succeeded phase (phase=%q)", op, op.Csv.Status.Phase)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(op.Namespace, op.Name,
				"Operator not in Succeeded state ", false).AddField(testhelper.OperatorPhase, string(op.Csv.Status.Phase)))
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

func testOperatorInstallationAccessToSCC(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject
	for i := range env.Operators {
		operator := env.Operators[i]
		csv := operator.Csv
		check.LogDebug("Checking operator %s", operator)
		clusterPermissions := csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions
		if len(clusterPermissions) == 0 {
			check.LogInfo("No clusterPermissions found in %s's CSV", operator)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(operator.Namespace, operator.Name,
				"No RBAC rules for Security Context Constraints found in CSV (no clusterPermissions found)", true))
			continue
		}

		// Fails in case any cluster permission has a rule that refers to securitycontextconstraints.
		if access.PermissionsHaveBadRule(clusterPermissions) {
			check.LogInfo("Operator %s has a rule for a service account to access cluster SCCs",
				operator)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(operator.Namespace, operator.Name, "One or more RBAC rules for Security Context Constraints found in CSV", false))
		} else {
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(operator.Namespace, operator.Name, "No RBAC rules for Security Context Constraints found in CSV", true))
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

func testOperatorOlmSubscription(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	for i := range env.Operators {
		operator := env.Operators[i]
		check.LogInfo("Testing Operator %q", operator)
		if operator.SubscriptionName == "" {
			check.LogError("OLM subscription not found for Operator %q", operator)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(env.Operators[i].Namespace, env.Operators[i].Name, "OLM subscription not found for operator, so it is not installed via OLM", false).
				AddField(testhelper.SubscriptionName, operator.SubscriptionName))
		} else {
			check.LogInfo("OLM subscription %q found for Operator %q", operator.SubscriptionName, operator)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(env.Operators[i].Namespace, env.Operators[i].Name, "install-status-no-privilege (subscription found)", true).
				AddField(testhelper.SubscriptionName, operator.SubscriptionName))
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

func testOperatorSingleCrdOwner(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	// Map each CRD to a list of operators that own it
	crdOwners := map[string][]string{}
	for i := range env.Operators {
		operator := env.Operators[i]
		ownedCrds := operator.Csv.Spec.CustomResourceDefinitions.Owned

		// Helper map to filter out different versions of the same CRD name.
		uniqueOwnedCrds := map[string]struct{}{}
		for j := range ownedCrds {
			uniqueOwnedCrds[ownedCrds[j].Name] = struct{}{}
		}

		// Now we can append the operator as CRD owner
		for crdName := range uniqueOwnedCrds {
			crdOwners[crdName] = append(crdOwners[crdName], operator.Name)
		}

		check.LogInfo("CRDs owned by operator %s: %+v", operator.Name, uniqueOwnedCrds)
	}

	// Flag those that are owned by more than one operator
	for crd, opList := range crdOwners {
		if len(opList) > 1 {
			check.LogError("CRD %q is owned by more than one operator (owners: %v)", crd, opList)
			nonCompliantObjects = append(nonCompliantObjects,
				testhelper.NewCrdReportObject(crd, "", "CRD is owned by more than one operator", false).
					AddField(testhelper.OperatorList, strings.Join(opList, ", ")))
		} else {
			check.LogDebug("CRD %q is owned by a single operator (%v)", crd, opList[0])
			compliantObjects = append(compliantObjects,
				testhelper.NewCrdReportObject(crd, "", "CRD is owned by a single operator", true).
					AddField(testhelper.OperatorName, opList[0]))
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

func testOperatorPodsNoHugepages(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	for csv, pods := range env.CSVToPodListMap {
		CsvResult := SplitCsv(csv)
		check.LogInfo("Name of csv: %q in namespaces: %q", CsvResult.NameCsv, CsvResult.Namespace)
		for _, pod := range pods {
			check.LogInfo("Testing Pod %q in namespace %q", pod.Name, pod.Namespace)
			if pod.HasHugepages() {
				check.LogError("Pod %q in namespace %q has hugepages", pod.Name, pod.Namespace)
				nonCompliantObjects = append(nonCompliantObjects, testhelper.NewPodReportObject(pod.Namespace, pod.Name, "Pod has hugepages", false))
			} else {
				check.LogInfo("Pod %q in namespace %q has no hugepages", pod.Name, pod.Namespace)
				compliantObjects = append(compliantObjects, testhelper.NewPodReportObject(pod.Namespace, pod.Name, "Pod has no hugepages", true))
			}
		}
		check.SetResult(compliantObjects, nonCompliantObjects)
	}
}

func testOperatorOlmSkipRange(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	for i := range env.Operators {
		operator := env.Operators[i]
		check.LogInfo("Testing Operator %q", operator)

		if operator.Csv.Annotations["olm.skipRange"] == "" {
			check.LogError("OLM skipRange not found for Operator %q", operator)
			nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(env.Operators[i].Namespace, env.Operators[i].Name, "OLM skipRange not found for operator", false))
		} else {
			check.LogInfo("OLM skipRange %q found for Operator %q", operator.Csv.Annotations["olm.skipRange"], operator)
			compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(env.Operators[i].Namespace, env.Operators[i].Name, "OLM skipRange found for operator", true).
				AddField("olm.SkipRange", operator.Csv.Annotations["olm.skipRange"]))
		}
	}
	check.SetResult(compliantObjects, nonCompliantObjects)
}

func testMultipleSameOperators(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	// Ensure the CSV name is unique and not installed more than once.
	// CSV Names are unique and OLM installs them with name.version format.
	// So, we can check if the CSV name is installed more than once.

	check.LogInfo("Checking if the operator is installed more than once")

	for _, op := range env.AllOperators {
		check.LogDebug("Checking operator %q", op.Name)
		check.LogDebug("Number of operators to check %s against: %d", op.Name, len(env.AllOperators))
		for _, op2 := range env.AllOperators {
			// Check if the operator is installed more than once.
			if OperatorInstalledMoreThanOnce(op, op2) {
				nonCompliantObjects = append(nonCompliantObjects, testhelper.NewOperatorReportObject(
					op.Namespace, op.Name, "Operator is installed more than once", false))
				break
			}
		}

		compliantObjects = append(compliantObjects, testhelper.NewOperatorReportObject(
			op.Namespace, op.Name, "Operator is installed only once", true))
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}

//nolint:funlen
func testOperatorCatalogSourceBundleCount(check *checksdb.Check, env *provider.TestEnvironment) {
	var compliantObjects []*testhelper.ReportObject
	var nonCompliantObjects []*testhelper.ReportObject

	const (
		bundleCountLimit = 1000

		// If the OCP version is <= 4.12, we need to use the probe container to get the bundle count.
		// This means we cannot use the package manifests to skip based on channel.
		ocpMajorVersion = 4
		ocpMinorVersion = 12
	)

	ocp412Skip := false
	// Check if the cluster is running an OCP version <= 4.12
	if env.OpenshiftVersion != "" {
		log.Info("Cluster is determined to be running Openshift version %q.", env.OpenshiftVersion)
		version, err := semver.NewVersion(env.OpenshiftVersion)
		if err != nil {
			log.Error("Failed to parse Openshift version %q.", env.OpenshiftVersion)
			check.LogError("Failed to parse Openshift version %q.", env.OpenshiftVersion)
			return
		}

		if version.Major() < ocpMajorVersion || (version.Major() == ocpMajorVersion && version.Minor() <= ocpMinorVersion) {
			log.Info("Cluster is running an OCP version <= 4.12.")
			ocp412Skip = true
		} else {
			log.Info("Cluster is running an OCP version > 4.12.")
		}
	}

	bundleCountLimitStr := strconv.Itoa(bundleCountLimit)

	// Loop through all labeled operators and check if they have more than 1000 referenced images.
	var catalogsAlreadyReported []string
	for _, op := range env.Operators {
		catalogSourceCheckComplete := false
		check.LogInfo("Checking bundle count for operator %q", op.Csv.Name)

		// Search through packagemanifests to match the name of the CSV.
		for _, pm := range env.AllPackageManifests {
			// Skip package manifests based on channel entries.
			// Note: This only works for OCP versions > 4.12 due to channel entries existence.
			if !ocp412Skip && catalogsource.SkipPMBasedOnChannel(pm.Status.Channels, op.Csv.Name) {
				log.Debug("Skipping package manifest %q based on channel", pm.Name)
				continue
			}

			// Search through all catalog sources to match the name and namespace of the package manifest.
			for _, catalogSource := range env.AllCatalogSources {
				if catalogSource.Name != pm.Status.CatalogSource || catalogSource.Namespace != pm.Status.CatalogSourceNamespace {
					log.Debug("Skipping catalog source %q based on name or namespace", catalogSource.Name)
					continue
				}

				// If the catalog source has already been reported, skip it.
				if stringhelper.StringInSlice(catalogsAlreadyReported, catalogSource.Name+"."+catalogSource.Namespace, false) {
					log.Debug("Skipping catalog source %q based on already reported", catalogSource.Name)
					continue
				}

				log.Debug("Found matching catalog source %q for operator %q", catalogSource.Name, op.Csv.Name)

				// The name and namespace match.  Lookup the bundle count.
				bundleCount := provider.GetCatalogSourceBundleCount(env, catalogSource)

				if bundleCount == -1 {
					check.LogError("Failed to get bundle count for CatalogSource %q", catalogSource.Name)
					nonCompliantObjects = append(nonCompliantObjects, testhelper.NewCatalogSourceReportObject(catalogSource.Namespace, catalogSource.Name, "Failed to get bundle count", false))
				} else {
					if bundleCount > bundleCountLimit {
						check.LogError("CatalogSource %q has more than "+bundleCountLimitStr+" ("+strconv.Itoa(bundleCount)+") referenced images", catalogSource.Name)
						nonCompliantObjects = append(nonCompliantObjects, testhelper.NewCatalogSourceReportObject(catalogSource.Namespace, catalogSource.Name, "CatalogSource has more than "+bundleCountLimitStr+" referenced images", false))
					} else {
						check.LogInfo("CatalogSource %q has less than "+bundleCountLimitStr+" ("+strconv.Itoa(bundleCount)+") referenced images", catalogSource.Name)
						compliantObjects = append(compliantObjects, testhelper.NewCatalogSourceReportObject(catalogSource.Namespace, catalogSource.Name, "CatalogSource has less than "+bundleCountLimitStr+" referenced images", true))
					}
				}

				log.Debug("Adding catalog source %q to list of already reported", catalogSource.Name)
				catalogsAlreadyReported = append(catalogsAlreadyReported, catalogSource.Name+"."+catalogSource.Namespace)
				// Signal that the catalog source check is complete.
				catalogSourceCheckComplete = true
				break
			}

			// If the catalog source check is complete, break out of the loop.
			if catalogSourceCheckComplete {
				break
			}
		}
	}

	check.SetResult(compliantObjects, nonCompliantObjects)
}
