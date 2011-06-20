all: coinsplit

coinsplit: coinsplit.c
	gcc -DUSE_TESTNET coinsplit.c -o coinsplit -ldb -lgmp -lcrypto
