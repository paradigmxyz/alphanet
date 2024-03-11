.PHONY: build-eip3074-bytecode
build-eip3074-bytecode:
	docker run --rm \
		-v $$(pwd)/crates/testing/resources/eip3074:/app/foundry \
		-u $$(id -u):$$(id -g) \
		ghcr.io/fgimenez/eip3074-tools:latest \
		--foundry-directory /app/foundry \
		--foundry-command build

.PHONY: check-eip3074-bytecode
check-eip3074-bytecode: build-eip3074-bytecode
	@if ! git diff --exit-code --quiet; then \
		echo "Error: There are uncommitted changes after the build. Please run 'make build-eip3074-bytecode' and commit the changes"; \
		exit 1; \
	fi
