# The docker image name
DOCKER_IMAGE_NAME ?= ghcr.io/paradigmxyz/alphanet

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

# The following commands use `cross` to build a cross-compile.
#
# These commands require that:
#
# - `cross` is installed (`cargo install cross`).
# - Docker is running.
# - The current user is in the `docker` group.
#
# The resulting binaries will be created in the `target/` directory.

# For aarch64, disable asm-keccak optimizations and set the page size for
# jemalloc. When cross compiling, we must compile jemalloc with a large page
# size, otherwise it will use the current system's page size which may not work
# on other systems. JEMALLOC_SYS_WITH_LG_PAGE=16 tells jemalloc to use 64-KiB
# pages. See: https://github.com/paradigmxyz/reth/issues/6742
build-aarch64-unknown-linux-gnu: FEATURES := $(filter-out asm-keccak,$(FEATURES))
build-aarch64-unknown-linux-gnu: export JEMALLOC_SYS_WITH_LG_PAGE=16

op-build-aarch64-unknown-linux-gnu: FEATURES := $(filter-out asm-keccak,$(FEATURES))
op-build-aarch64-unknown-linux-gnu: export JEMALLOC_SYS_WITH_LG_PAGE=16

# No jemalloc on Windows
build-x86_64-pc-windows-gnu: FEATURES := $(filter-out jemalloc jemalloc-prof,$(FEATURES))

##@ Docker

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --driver docker-container --name cross-builder`
.PHONY: docker-build-push
docker-build-push: ## Build and push a cross-arch Docker image tagged with the latest git tag.
	$(call docker_build_push,$(GIT_TAG),$(GIT_TAG))

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --driver docker-container --name cross-builder`
.PHONY: docker-build-push-latest
docker-build-push-latest: ## Build and push a cross-arch Docker image tagged with the latest git tag and `latest`.
	$(call docker_build_push,$(GIT_TAG),latest)

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --name cross-builder`
.PHONY: docker-build-push-nightly
docker-build-push-nightly: ## Build and push cross-arch Docker image tagged with the latest git tag with a `-nightly` suffix, and `latest-nightly`.
	$(call docker_build_push,$(GIT_TAG)-nightly,latest-nightly)

# Create a cross-arch Docker image with the given tags and push it
define docker_build_push
	$(MAKE) build-x86_64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/amd64
	cp $(BUILD_PATH)/x86_64-unknown-linux-gnu/$(PROFILE)/alphanet $(BIN_DIR)/amd64/alphanet

	$(MAKE) build-aarch64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/arm64
	cp $(BUILD_PATH)/aarch64-unknown-linux-gnu/$(PROFILE)/alphanet $(BIN_DIR)/arm64/alphanet

	docker buildx build --file ./Dockerfile.cross . \
		--platform linux/amd64,linux/arm64 \
		--tag $(DOCKER_IMAGE_NAME):$(1) \
		--tag $(DOCKER_IMAGE_NAME):$(2) \
		--provenance=false \
		--push
endef
