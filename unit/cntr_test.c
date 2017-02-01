/*
 * Copyright (c) 2013-2017 Intel Corporation.  All rights reserved.
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

#include <rdma/fi_errno.h>

#include "unit_common.h"
#include "shared.h"

static char err_buf[512];

static int cntr_open_close()
{
	int i, opened;
	int ret = 0;
	int testret = FAIL;
	struct fid_cntr **cntrs = calloc(fi->domain_attr->cntr_cnt,
					 sizeof(struct fid_cntr *));
	if (!cntrs) {
	 	perror("calloc");
		return -FI_ENOMEM;
	}	
	
	for (opened = 0; opened < fi->domain_attr->cntr_cnt; opened++) {
		ret = ft_cntr_open(&cntrs[opened]);
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			break;
		}
	}

	for (i = 0; i < opened; i++) {
		ret = fi_close(&(cntrs[i])->fid);
		if (ret) {
			FT_PRINTERR("fi_cntr_close", ret);
			goto fail;
		}
	}
	if (opened == fi->domain_attr->cntr_cnt)	
		testret = PASS;

fail:
	free(cntrs);
	return TEST_RET_VAL(ret, testret);
}

struct test_entry test_array[] = {
	TEST_ENTRY(cntr_open_close, "Test open/close counters to limit"),
	{ NULL, "" }
};

static void usage(void)
{
	ft_unit_usage("cntr_test", "Unit test for counter (cntr)");
}

int main(int argc, char **argv)
{
	int op, ret;
	int failed;

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
	ret = fi_getinfo(FT_FIVERSION, NULL, 0, 0, hints, &fi);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		goto err;
	}
	ft_open_fabric_res();

	printf("Testing CNTRS on fabric %s\n", fi->fabric_attr->name);

	failed = run_tests(test_array, err_buf);
	if (failed > 0)
		printf("Summary: %d tests failed\n", failed);
	else
		printf("Summary: all tests passed\n");

err:
	ft_free_res();
	return ret ? ft_exit_code(ret) : (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
