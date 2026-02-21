//
// Wallet abstraction integration tests against testnut.cashu.space.
// Tests the full wallet_* API (mint → balance → send → receive → melt).
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "testing_utils.h"
#include "../cashu/http.h"
#include "../cashu/protocol.h"
#include "../cashu/errors.h"
#include "../abstractions/wallet.h"

static int pass_count  = 0;
static int total_count = 0;

#define MINT_URL     "https://testnut.cashu.space"
#define STORAGE_PATH "/tmp/test_wallet_proofs.json"


// mint `amount` sat into the wallet via the full 2-step quote flow.
static cashu_err_t do_mint(uint64_t amount) {
    mint_quote_t q;
    cashu_err_t err = wallet_mint_quote(amount, &q);
    if (err != CASHU_OK) return err;

    printf("  (waiting 6s for testnut to auto-pay %llu sat...)\n",
           (unsigned long long)amount);
    sleep(6);

    mint_quote_t q2;
    err = wallet_mint_quote_state(q.quote, &q2);
    if (err != CASHU_OK || strcmp(q2.state, "PAID") != 0) {
        mint_quote_free(&q); mint_quote_free(&q2);
        return CASHU_ERR_PROTOCOL;
    }
    mint_quote_free(&q2);

    err = wallet_mint(q.quote, amount);
    mint_quote_free(&q);
    return err;
}


static void test_mint_and_balance(void) {
    uint64_t before = wallet_balance();
    cashu_err_t err = do_mint(8);
    ASSERT(err == CASHU_OK, "wallet: mint 8 sat OK");

    uint64_t after = wallet_balance();
    ASSERT(after == before + 8, "wallet: balance increased by 8");
    printf("  (balance: %llu → %llu)\n",
           (unsigned long long)before, (unsigned long long)after);
}

static void test_send_receive(void) {
    uint64_t before = wallet_balance();
    if (before < 4) {
        printf("  (insufficient balance for send test, skipping)\n");
        return;
    }

    // send 4 sat — returns a cashuB token
    char *token = NULL;
    cashu_err_t err = wallet_send(4, &token);
    ASSERT(err == CASHU_OK,   "wallet: send 4 sat OK");
    ASSERT(token != NULL,     "wallet: token not NULL");
    if (err != CASHU_OK || !token) { free(token); return; }

    ASSERT(strncmp(token, "cashuB", 6) == 0, "wallet: token starts with cashuB");
    printf("  (token len=%zu)\n", strlen(token));

    // balance should have decreased (by 4 + fee)
    uint64_t mid = wallet_balance();
    ASSERT(mid < before, "wallet: balance decreased after send");

    // receive the same token back - swaps into own keyset
    err = wallet_receive(token);
    ASSERT(err == CASHU_OK, "wallet: receive own token OK");

    uint64_t after = wallet_balance();
    // after == mid + (4 - receive_fee); receive_fee >= 0
    ASSERT(after > mid, "wallet: balance increased after receive");
    printf("  (balance: %llu → %llu → %llu)\n",
           (unsigned long long)before,
           (unsigned long long)mid,
           (unsigned long long)after);

    free(token);
}

static void test_melt(void) {
    // create a 1-sat mint quote to use as melt target (circular pay on testnut)
    mint_quote_t pay_q;
    cashu_err_t err = wallet_mint_quote(1, &pay_q);
    ASSERT(err == CASHU_OK, "wallet: melt target mint_quote OK");
    if (err != CASHU_OK) return;

    melt_quote_t melt_q;
    err = wallet_melt_quote(pay_q.request, &melt_q);
    ASSERT(err == CASHU_OK, "wallet: melt_quote OK");
    if (err != CASHU_OK) { mint_quote_free(&pay_q); return; }

    uint64_t needed = melt_q.amount + melt_q.fee_reserve;
    uint64_t bal    = wallet_balance();
    printf("  (balance=%llu needed=%llu)\n",
           (unsigned long long)bal, (unsigned long long)needed);

    if (bal < needed) {
        printf("  (insufficient balance for melt, skipping)\n");
        goto cleanup;
    }

    err = wallet_melt(&melt_q);
    ASSERT(err == CASHU_OK, "wallet: melt OK");

    uint64_t after = wallet_balance();
    ASSERT(after < bal, "wallet: balance decreased after melt");
    printf("  (balance after melt: %llu)\n", (unsigned long long)after);

cleanup:
    melt_quote_free(&melt_q);
    mint_quote_free(&pay_q);
}


int main(void) {
    cashu_http_init();
    crypto_init();

    // clean slate for each run
    remove(STORAGE_PATH);
    remove(STORAGE_PATH ".tmp");

    cashu_err_t err = wallet_init(MINT_URL, STORAGE_PATH, "sat");
    if (err != CASHU_OK) {
        fprintf(stderr, "wallet_init failed: %d\n", err);
        return 1;
    }

    printf("================= wallet tests (%s) =================\n", MINT_URL);

    test_mint_and_balance();
    test_send_receive();
    test_melt();

    printf("\n%d/%d passed\n", pass_count, total_count);

    wallet_term();
    crypto_free();
    cashu_http_term();
    return pass_count == total_count ? 0 : 1;
}
