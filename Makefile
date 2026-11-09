.DEFAULT_GOAL := deploy

CLAB := containerlab
TOPOLOGY := topo.clab.yml
CLIENTS ?= 10
INTERVAL ?= 1
PACKET_HANDLING_MODE ?= filter
HASH_ALGORITHM ?= halfsiphash

validate_hash = $(if $(and $(filter 1,$(words $(HASH_ALGORITHM))),$(filter fnv1a murmur3 halfsiphash,$(HASH_ALGORITHM))),,$(error Set HASH_ALGORITHM to fnv1a, murmur3 or halfsiphash))
SNAPSHOT ?= select
SKIP_PROMPT ?= 0

shell_quote = '$(subst ','"'"',$(1))'

export CLAB_LABDIR_BASE ?= /tmp

ANALYSIS_TARGETS := analysis-threshold-first-drop \
	analysis-threshold-passed-syns \
	analysis-threshold-attack-drop \
	analysis-confusion-matrix \
	analysis-boxplot-first-drop \
	analysis-epoch-boundary \
	analysis-heatmap-epoch-attack \
	analysis-heatmap-epoch-legitimate \
	analysis-heatmap-ubf-attack \
	analysis-heatmap-ubf-legitimate \
	analysis-histogram-ubf \
	analysis-time-series \
	analysis-hash-comparison \
	analysis-hash-comparison-primes \
	analysis-halfsiphash-ubf-sweep \
	analysis-hash-avalanche \
	analysis-hash-port-bits

.PHONY: help build deploy destroy graph client attack mode config show reset analysis save download $(ANALYSIS_TARGETS)

help:
	@printf '%s\n' 'Usage:' '  make <command> [VARIABLE=value ...]' '' 'Commands:'
	@printf '  %-14s %s\n' \
		'make help'    'Show this help.' \
		'make build'   'Build the node image.' \
		'make deploy'  'Build the image and deploy the lab.' \
		'make destroy' 'Destroy the lab.' \
		'make analysis' 'Render analyses with one lab per graph and resets between runs; reuse matching cache; use -j4 for parallel runs.' \
		'make save'    'Save analysis and cache to S3; prompt for a name (Enter uses date and time).' \
		'make download' 'Select a saved analysis and cache with fzf; use SNAPSHOT=<id> or latest to skip selection.' \
		'make graph'   'Serve the topology graph at http://localhost:50080.' \
		'make mode'    'Change the running firewall mode.' \
		'make config'  'Update one or more runtime parameters.' \
		'make show'    'Show the current mode and detector parameters.' \
		'make reset'   'Clear detector history without changing mode or statistics.' \
		'make client'  'Send HTTP requests and log attempts.' \
		'make attack'  'Send SYN packets with hping3 and log attempts.'
	@printf '%s\n' '' 'Examples:' \
		'  make mode PACKET_HANDLING_MODE=filter' \
		'    PACKET_HANDLING_MODE defaults to filter: allow, block or filter.' \
		'' \
		'  make config EPOCH_TIME_MS=2000 SYN_COUNT_BLOCK_THRESHOLD=3 UBF_SIZE=2048' \
		'    Set EPOCH_TIME_MS, SYN_COUNT_BLOCK_THRESHOLD and/or UBF_SIZE (1..8192).' \
		'  make config HASH_ALGORITHM=murmur3' \
		'  make config HASH_ALGORITHM=halfsiphash' \
		'    make config always selects HASH_ALGORITHM (default: halfsiphash).' \
		'    Pause traffic before changing hash or UBF_SIZE; history is cleared.' \
		'  make analysis HASH_ALGORITHM=fnv1a' \
		'    All analyses default to halfsiphash; choices: fnv1a, murmur3, halfsiphash.' \
		'' \
		'  make client CLIENTS=10 INTERVAL=1' \
		'  make attack CLIENTS=10 INTERVAL=1' \
		'    Both commands default to CLIENTS=10 and INTERVAL=1.' \
		'' \
		'  make save' \
		'  make save NAME=experiment-01' \
		'  make save SKIP_PROMPT=1' \
		'    Names are appended to the UTC timestamp; Enter, NAME= or SKIP_PROMPT=1 uses the timestamp alone.' \
		'  make download' \
		'  make download SNAPSHOT=2026-11-05T22-30-00.000000Z' \
		'    Fixed bucket: syn-flood-detect-tcc-luiz; requires AWS CLI credentials (AWS_PROFILE is supported).' \
		'    Interactive downloads require fzf; snapshots are listed newest first, in UTC.' \
		'    Restores matching files under results/analysis; preserves unrelated local files.'

build:
	@test "$$(uname -sm)" = 'Linux x86_64' || { echo 'The lab requires Linux x86_64.' >&2; exit 1; }
	docker build --platform linux/amd64 -t node:local .

deploy: build
	mkdir -p results/packets
	$(CLAB) deploy -t "$(TOPOLOGY)" --skip-labdir-acl

destroy:
	$(CLAB) destroy -t "$(TOPOLOGY)" --cleanup

graph:
	$(CLAB) graph -t "$(TOPOLOGY)"

mode:
	$(if $(filter undefined,$(origin EBPF_MODE)),,$(error EBPF_MODE was renamed; use PACKET_HANDLING_MODE))
	$(if $(and $(filter 1,$(words $(PACKET_HANDLING_MODE))),$(filter allow block filter,$(PACKET_HANDLING_MODE))),,$(error Set PACKET_HANDLING_MODE to allow, block or filter))
	docker exec clab-topo-firewall /usr/local/bin/syn-flood-detect mode "$(PACKET_HANDLING_MODE)"

config:
	$(validate_hash)
	docker exec clab-topo-firewall /usr/local/bin/syn-flood-detect config --hash-algorithm "$(HASH_ALGORITHM)" $(if $(filter undefined,$(origin EPOCH_TIME_MS)),,--epoch-time-ms "$(EPOCH_TIME_MS)") $(if $(filter undefined,$(origin SYN_COUNT_BLOCK_THRESHOLD)),,--syn-count-block-threshold "$(SYN_COUNT_BLOCK_THRESHOLD)") $(if $(filter undefined,$(origin UBF_SIZE)),,--ubf-size "$(UBF_SIZE)")

show:
	docker exec clab-topo-firewall /usr/local/bin/syn-flood-detect show

reset:
	docker exec clab-topo-firewall /usr/local/bin/syn-flood-detect reset

client:
	python3 ./scripts/simulate-clients.py "$(CLIENTS)" "$(INTERVAL)"

attack:
	python3 ./scripts/simulate-attack.py "$(CLIENTS)" "$(INTERVAL)"

analysis: $(ANALYSIS_TARGETS)

save:
	python3 scripts/analysis-storage.py save $(if $(filter undefined,$(origin NAME)),,--name $(call shell_quote,$(NAME))) $(if $(filter 1,$(SKIP_PROMPT)),--skip-prompt)

download:
	python3 scripts/analysis-storage.py download --snapshot $(call shell_quote,$(SNAPSHOT))

analysis-threshold-first-drop: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2,10,20 --ubf-size 2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-threshold-passed-syns: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2,10,20 --ubf-size 2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-threshold-attack-drop: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2,10,20 --ubf-size 2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-confusion-matrix: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2,10,20 --ubf-size 2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-boxplot-first-drop: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2,10,20 --ubf-size 2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-epoch-boundary: ANALYSIS_ARGS = --epoch-time-ms 1,45,55,75,95,105,150,195,205,250 --syn-count-block-threshold 3 --ubf-size 2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.05,0.1,0.2 --duration 5 \
	--repetitions 1

analysis-heatmap-epoch-attack: ANALYSIS_ARGS = --epoch-time-ms 50,100,150 --syn-count-block-threshold 2,20 --ubf-size 128 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-heatmap-epoch-legitimate: ANALYSIS_ARGS = --epoch-time-ms 50,100,150 --syn-count-block-threshold 2,20 --ubf-size 128 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-heatmap-ubf-attack: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2 --ubf-size 8,64,128,256,512,1024 \
	--sources 10,50,100,200 --attacker-percent 20 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-heatmap-ubf-legitimate: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 2 --ubf-size 8,64,128,256,512,1024 \
	--sources 10,50,100,200 --attacker-percent 20 --client-interval 0.1 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-histogram-ubf: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 3 --ubf-size 8,64,256,2048 \
	--clients 15 --attackers 15 --client-interval 0.5 --attack-interval 0.1 --duration 5 \
	--repetitions 1

analysis-time-series: ANALYSIS_ARGS = --epoch-time-ms 500 --syn-count-block-threshold 3 --ubf-size 2048 \
	--clients 2 --attackers 3 --client-interval 0.5 --attack-interval 0.1 --duration 10 \
	--before 2 --after 2 --bin-seconds 0.5

analysis-hash-comparison: ANALYSIS_ARGS = --ubf-size 8192 \
	--sources 100,200,250,300,400,500,600,700,800,900,1000,1100,1200,1300,1400,1500,1600,1700,1800,1900,2000 --attacker-percent 50 \
	--repetitions 5

analysis-hash-comparison-primes: ANALYSIS_ARGS = --ubf-size 8191 \
	--sources 100,200,250,300,400,500,600,700,800,900,1000,1100,1200,1300,1400,1500,1600,1700,1800,1900,2000 --attacker-percent 50 \
	--repetitions 5

analysis-halfsiphash-ubf-sweep: ANALYSIS_ARGS = --ubf-center 4096 --ubf-radius 20 \
	--sources 2000 --attacker-percent 50 \
	--repetitions 200

analysis-hash-avalanche: ANALYSIS_ARGS = --sources 2000 --attacker-percent 50

analysis-hash-port-bits: ANALYSIS_ARGS = --ubf-size 1024 \
	--keys 16,32,64,96,128,160,192,224,256 \
	--src-ip 104.16.1.1 --dst-ip 203.0.113.2 --port-base 80 \
	--port-bits 4,5,6,7,12,13,14,15

$(ANALYSIS_TARGETS):
	$(validate_hash)
	@nix-shell analysis/shell.nix --run 'set -eu; \
		mkdir -p results/analysis; \
		python3 analysis/$(subst -,_,$(patsubst analysis-%,%,$@)).py $(ANALYSIS_ARGS) $(if $(filter-out analysis-hash-comparison analysis-hash-comparison-primes analysis-halfsiphash-ubf-sweep analysis-hash-avalanche analysis-hash-port-bits,$@),--hash-algorithm "$(HASH_ALGORITHM)") \
			--out "results/analysis/$(subst -,_,$(patsubst analysis-%,%,$@)).png"'
