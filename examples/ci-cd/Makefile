.PHONY: dist build run upload_sbom


#
# Dependency-Track settings (optional)
#
# See: https://docs.dependencytrack.org/
#
# If you use Dependabot in GitHub or similar, you don't need this.
#

include .env

export OWASP_DTRACK_URL
export OWASP_DTRACK_VERIFY_SSL
export OWASP_DTRACK_API_KEY

build:
	docker build -t pipcanary-cicd .

run:
	rm -rf shared/*
	cp pyproject.toml shared
	docker run --privileged -v "$(PWD)/shared:/var/shared" pipcanary-cicd

# Uploads SBOM to Dependency-Track and analyzes it (optional) 
# see: 
#	- https://github.com/mreiche/owasp-dependency-track-cli
#	- https://docs.dependencytrack.org/
# 
upload_sbom: 
	owasp-dtrack-cli upload --project-name $(PROJECT_NAME)  --project-version $(VERSION) --latest --parent-uuid $(UUID) --auto-create $(PARENT_PROJECT_UUID) shared/requirements-locked.sbom.cdx.json
	owasp-dtrack-cli analyze --project-name $(PROJECT_NAME)
