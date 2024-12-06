package results

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/redhat-best-practices-for-k8s/certsuite/internal/log"
)

const (
	// tarGz file prefix layout format: YearMonthDay-HourMinSec
	tarGzFileNamePrefixLayout = "20060102-150405"
	tarGzFileNameSuffix       = "cnf-test-results.tar.gz"

	// Connect API Information
	connectAPIURL = "https://access.qa.redhat.com/hydra/cwe/rest/v1.0/attachments/upload"
)

func generateZipFileName() string {
	return fmt.Sprintf(time.Now().Format(tarGzFileNamePrefixLayout) + "-" + tarGzFileNameSuffix)
}

// Helper function to get the tar file header from a file.
func getFileTarHeader(file string) (*tar.Header, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info from %s: %v", file, err)
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get file info header for %s: %v", file, err)
	}

	return header, nil
}

// Creates a zip file in the outputDir containing each file in the filePaths slice.
func CompressResultsArtifacts(outputDir string, filePaths []string) (string, error) {
	zipFileName := generateZipFileName()
	zipFilePath := filepath.Join(outputDir, zipFileName)

	log.Info("Compressing results artifacts into %s", zipFilePath)
	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		return "", fmt.Errorf("failed creating tar.gz file %s in dir %s (filepath=%s): %v",
			zipFileName, outputDir, zipFilePath, err)
	}

	zipWriter := gzip.NewWriter(zipFile)
	defer zipWriter.Close()

	tarWriter := tar.NewWriter(zipWriter)
	defer tarWriter.Close()

	for _, file := range filePaths {
		log.Debug("Zipping file %s", file)

		tarHeader, err := getFileTarHeader(file)
		if err != nil {
			return "", err
		}

		err = tarWriter.WriteHeader(tarHeader)
		if err != nil {
			return "", fmt.Errorf("failed to write tar header for %s: %v", file, err)
		}

		f, err := os.Open(file)
		if err != nil {
			return "", fmt.Errorf("failed to open file %s: %v", file, err)
		}

		if _, err = io.Copy(tarWriter, f); err != nil {
			return "", fmt.Errorf("failed to tar file %s: %v", file, err)
		}

		f.Close()
	}

	// Return the entire path to the zip file
	return zipFilePath, nil
}

func createFormField(w *multipart.Writer, field, value string) error {
	_, err := w.CreateFormField(field)
	if err != nil {
		return fmt.Errorf("failed to create form field: %v", err)
	}

	err = w.WriteField(field, value)
	if err != nil {
		return fmt.Errorf("failed to write field %s: %v", field, err)
	}

	return nil
}

// curl example:
// curl --location 'https://access.qa.redhat.com/hydra/cwe/rest/v1.0/attachments/upload' \
// --header 'x-api-key: API_KEY' \
// --form 'type="RhocpBestPracticeTestResult"' \
// --form 'attachment=@"/Users/yangli/Downloads/rhocp-best-practice-test-results/20240925-143237-cnf-test-results.tar.gz"' \
// --form 'certId="652787"' \
// --form 'description="aaa"'

func SendResultsToConnectAPI(zipFile, apiKey, projectID string) error {
	log.Info("Sending results to Red Hat Connect")

	var (
		buf = new(bytes.Buffer)
	)

	// Create a new multipart writer
	w := multipart.NewWriter(buf)
	defer w.Close()

	_, err := w.CreateFormFile("attachment", filepath.Base(zipFile))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	// Create a form field
	err = createFormField(w, "type", "RhocpBestPracticeTestResult")
	if err != nil {
		return err
	}

	// Create a form field
	err = createFormField(w, "certId", projectID)
	if err != nil {
		return err
	}

	// Create a form field
	err = createFormField(w, "description", "CNF Test Results")
	if err != nil {
		return err
	}

	// Create a new request
	req, err := http.NewRequest("POST", connectAPIURL, buf)
	if err != nil {
		return fmt.Errorf("failed to create new request: %v", err)
	}

	// Set the content type
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("x-api-key", apiKey)

	// Create a client
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send post request to the endpoint: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send post request to the endpoint: %v", res.Status)
	}

	return nil
}
