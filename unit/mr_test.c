/*
 * Copyright (c) 2013-2016 Intel Corporation.  All rights reserved.
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <rdma/fi_domain.h>
#include <rdma/fi_errno.h>

#include "unit_common.h"
#include "shared.h"

static char err_buf[512];

/*
 * Tests:
 */
static int mr_reg()
{
	int i, j;
	int ret = 0;
	int testret = FAIL;
	struct fid_mr *mr;
	uint64_t access;
	uint64_t *access_combinations;
	int len = 0;

	access = ft_info_to_mr_access(fi);
	ret = ft_alloc_bit_combo(0, access, &access_combinations, &len);
	if (ret) {
		FT_UNIT_STRERR(err_buf, "ft_alloc_bit_combo failed", ret);
		goto fail;
	}

	for (i = 0; i < test_cnt; i++) {
		buf_size = test_size[i].size;
		for (j = 0; j < len; j++) {
			ret = fi_mr_reg(domain, buf, buf_size, access_combinations[j], 0,
					FT_MR_KEY, 0, &mr, NULL);
			if (ret) {
				FT_UNIT_STRERR(err_buf, "fi_mr_reg failed", ret);
				goto fail;
			}

			ret = fi_close(&mr->fid);
			if (ret) {
				FT_UNIT_STRERR(err_buf, "fi_close failed", ret);
				goto fail;
			}
		}
	}
	testret = PASS;
fail:
	ft_free_bit_combo(access_combinations);
	return TEST_RET_VAL(ret, testret);
}

static int mr_regv()
{
	int i, j, n;
	int ret = 0;
	int testret = FAIL;
	struct fid_mr *mr;
	struct iovec *iov;
	char *base;

	if (!fi->domain_attr->mr_iov_limit) {
		ret = 1;
		FT_UNIT_STRERR(err_buf, "fi_mr_regv failed, mr_iov_limit", ret);
		goto fail;
	}

	iov = calloc(fi->domain_attr->mr_iov_limit, sizeof(*iov));
	if (!iov) {
		perror("calloc");
		return FI_ENOMEM;
	}

	for (i = 0; i < test_cnt &&
	     test_size[i].size <= fi->domain_attr->mr_iov_limit; i++) {
		n = test_size[i].size;
		base = buf;

		for (j = 0; j < n; j++) {
			iov[j].iov_base = base;
			iov[j].iov_len = test_size[test_cnt - 1].size / n;
			base += iov[j].iov_len;			
		}

		ret = fi_mr_regv(domain, &iov[0], n, ft_info_to_mr_access(fi), 0,
				 FT_MR_KEY, 0, &mr, NULL);
		if (ret) {
			FT_UNIT_STRERR(err_buf, "fi_mr_regv failed", ret);
			goto clean;
		}

		ret = fi_close(&mr->fid);
		if (ret) {
			FT_UNIT_STRERR(err_buf, "fi_close failed", ret);
			goto clean;
		}
	}
	testret = PASS;
clean:
	free(iov);
fail:
	return TEST_RET_VAL(ret, testret);
}

static int mr_regattr()
{
	int i, j, n;
	int ret = 0;
	int testret = FAIL;
	struct fid_mr *mr;
	struct iovec *iov;
	struct fi_mr_attr attr;
	char *base;

	if (!fi->domain_attr->mr_iov_limit) {
		ret = 1;
		FT_UNIT_STRERR(err_buf, "fi_mr_regattr failed, mr_iov_limit", ret);
		goto fail;
	}

	attr.access = ft_info_to_mr_access(fi);
	attr.requested_key = FT_MR_KEY;
	attr.context = NULL;
	
	iov = calloc(fi->domain_attr->mr_iov_limit, sizeof(*iov));
	if (!iov) {
		perror("calloc");
		return -FI_ENOMEM;
	}

	for (i = 0; i < test_cnt &&
	     test_size[i].size <= fi->domain_attr->mr_iov_limit; i++) {
		
		n = test_size[i].size;
		base = buf;
		for (j = 0; j < n; j++) {
			iov[j].iov_base = base;
			iov[j].iov_len = test_size[test_cnt - 1].size / n;
			base += iov[j].iov_len;
		}

		attr.iov_count = n;
		attr.mr_iov = &iov[0];
		ret = fi_mr_regattr(domain, &attr, 0, &mr);
		if (ret) {
			FT_UNIT_STRERR(err_buf, "fi_mr_regattr failed", ret);
			goto clean;
		}

		ret = fi_close(&mr->fid);
		if (ret) {
			FT_UNIT_STRERR(err_buf, "fi_close failed", ret);
			goto clean;
		}
	}
	testret = PASS;
clean:
	free(iov);
fail:
	return TEST_RET_VAL(ret, testret);
}

struct test_entry test_array[] = {
	TEST_ENTRY(mr_reg, "Test fi_mr_reg across different access combinations"),
	TEST_ENTRY(mr_regv, "Test fi_mr_regv across various buffer sizes"),
	TEST_ENTRY(mr_regattr, "Test fi_mr_regattr across various buffer sizes"),
	{ NULL, "" }
};

static void usage(void)
{
	ft_unit_usage("mr_test", "Unit test for Memory Region (MR)");
}

int main(int argc, char **argv)
{
	int op, ret;
	int failed;

	buf = NULL;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, FAB_OPTS "h")) != -1) {
		switch (op) {
		default:
			ft_parseinfo(op, optarg, hints);
			break;
		case '?':
		case 'h':
			usage();
			return EXIT_FAILURE;
		}
	}

	hints->mode = ~0;

	hints->caps |= FI_MSG | FI_RMA;

	ret = fi_getinfo(FT_FIVERSION, NULL, 0, 0, hints, &fi);
	if (ret) {
		hints->caps &= ~FI_RMA;
		ret = fi_getinfo(FT_FIVERSION, NULL, 0, 0, hints, &fi);
		if (ret) {
			FT_PRINTERR("fi_getinfo", ret);
			goto err;
		}
	}

	ret = ft_open_fabric_res();
	if (ret)
		goto err;

	buf = malloc(test_size[test_cnt - 1].size);
	if (!buf) {
		ret = -FI_ENOMEM;
		goto err;
	}

	printf("Testing MR on fabric %s\n", fi->fabric_attr->name);

	failed = run_tests(test_array, err_buf);
	if (failed > 0) {
		printf("Summary: %d tests failed\n", failed);
	} else {
		printf("Summary: all tests passed\n");
	}

err:
	ft_free_res(); // frees buf as well
	return ret ? -ret : (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
