.PHONY: all

all: kill
	@cargo fmt
	@cargo build
	@mkdir -p bin
	@cp target/debug/mpc_hd_gg18 bin/mpc_hd_gg18

kill:
	@tmux kill-session -t MpcHdGg18 || true

keygen: kill
	@tmux new-session -s MpcHdGg18 \
		-n man -d ";" new-window \
		-n  k1 -d ";" new-window \
		-n  k2 -d ";" new-window \
		-n  k3 -d ";" new-window \
		-n  k4 -d ";" new-window \
		-n  k5 -d ";" 
	@sleep 1
	@tmux send-keys -t MpcHdGg18:man "cd $(shell pwd)/bin && ./mpc_hd_gg18 manager" C-m
	@tmux send-keys -t MpcHdGg18:k1 "cd $(shell pwd)/bin && ./mpc_hd_gg18 keygen k1.json 2/5" C-m
	@tmux send-keys -t MpcHdGg18:k2 "cd $(shell pwd)/bin && ./mpc_hd_gg18 keygen k2.json 2/5" C-m
	@tmux send-keys -t MpcHdGg18:k3 "cd $(shell pwd)/bin && ./mpc_hd_gg18 keygen k3.json 2/5" C-m
	@tmux send-keys -t MpcHdGg18:k4 "cd $(shell pwd)/bin && ./mpc_hd_gg18 keygen k4.json 2/5" C-m
	@tmux send-keys -t MpcHdGg18:k5 "cd $(shell pwd)/bin && ./mpc_hd_gg18 keygen k5.json 2/5" C-m

sign: kill
	@tmux new-session -s MpcHdGg18 \
		-n man -d ";" new-window \
		-n  k1 -d ";" new-window \
		-n  k2 -d ";" new-window \
		-n  k3 -d ";" new-window \
		-n  k4 -d ";" new-window \
		-n  k5 -d ";" 
	@sleep 1
	@tmux send-keys -t MpcHdGg18:man "cd $(shell pwd)/bin && ./mpc_hd_gg18 manager" C-m
	@tmux send-keys -t MpcHdGg18:k1 "cd $(shell pwd)/bin && ./mpc_hd_gg18 sign k4.json 2/5/5 JeNeSaisPas" C-m
	@tmux send-keys -t MpcHdGg18:k2 "cd $(shell pwd)/bin && ./mpc_hd_gg18 sign k1.json 2/5/5 JeNeSaisPas" C-m
	@tmux send-keys -t MpcHdGg18:k3 "cd $(shell pwd)/bin && ./mpc_hd_gg18 sign k5.json 2/5/5 JeNeSaisPas" C-m
	@tmux send-keys -t MpcHdGg18:k4 "cd $(shell pwd)/bin && ./mpc_hd_gg18 sign k2.json 2/5/5 JeNeSaisPas" C-m
	@tmux send-keys -t MpcHdGg18:k5 "cd $(shell pwd)/bin && ./mpc_hd_gg18 sign k3.json 2/5/5 JeNeSaisPas" C-m