/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <signal.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/wait.h>

#include <doca_dpi.h>

#include <cmdline_socket.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline.h>

#include <rte_compat.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_sft.h>

#include "flow_offload.h"
#include "dpi_worker.h"
#include "utils.h"

DOCA_LOG_REGISTER(UFLTR);

#define CLIENT_ID 0x1A

#define DEFAULT_TXT_INPUT "/tmp/signature.txt"
#define DEFAULT_CDO_OUTPUT "/tmp/signature.cdo"
#define MAX_COMMAND_LENGTH 255
#define COMPILER_PATH "/usr/bin/doca_dpi_compiler"

static uint32_t global_sig_id;

static struct doca_dpi_ctx *dpi_ctx;

enum app_args {
	ARG_HELP = 'h',
	ARG_PRINT_MATCH = 'p',
	ARG_CT = 't',
	ARG_LOG_LEVEL = 'l',
};

struct url_config {
	bool print_on_match;
	bool ct;
};

/*
	删除文件，并重新打卡同名文件
*/
static void
create_database(char *signature_filename)
{
	FILE *url_signature_file;
	int errno_output;

	if (remove(signature_filename) != 0) {
		errno_output = errno;
		DOCA_LOG_DBG("File removal failed : error %d", errno_output);
	}
	url_signature_file = fopen((char *)signature_filename, "w");
	if (url_signature_file == NULL) {
		DOCA_LOG_ERR("Failed to open signature file");
		return;
	}
	fclose(url_signature_file);
	global_sig_id = 1;
}

/*
	编译并加载特征
	两个参数分别是特征文件路径和生成的cdo文件路径
*/
static void
compile_and_load_signatures(char *signature_filename, char *cdo_filename)
{
	int status, errno_output;
	char command_buffer[MAX_COMMAND_LENGTH];

	if (access(signature_filename, F_OK) != 0) {
		DOCA_LOG_ERR("Signature file is missing - check PATH=%s\n or \"create database\"",
			 signature_filename);
		return;
	}

	// 应该是将命令行写入到command_buffer中
	status = snprintf(command_buffer, MAX_COMMAND_LENGTH, "%s -i %s -o %s -f suricata",
		COMPILER_PATH, signature_filename, cdo_filename);
	if (status == MAX_COMMAND_LENGTH) {
		DOCA_LOG_ERR("File path too long, please shorten and try again");
		return;
	}
	status = system(command_buffer);
	if (status != 0) {
		errno_output = errno;
		APP_EXIT("Signature file compilation failed : error %d", errno_output);
	}
	if (doca_dpi_load_signatures(dpi_ctx, cdo_filename) != 0)
		APP_EXIT("Loading DPI signature failed");
}

/*
	写特征文件
*/
static void
create_url_signature(const char *signature_filename, uint32_t sig_id, const char *msg,
		     const char *pcre)
{
	FILE *url_signature_file;

	url_signature_file = fopen((char *)signature_filename, "a");
	if (url_signature_file == NULL) {
		DOCA_LOG_ERR("Failed to open signature file");
		return;
	}

	fprintf(url_signature_file, "drop tcp any any -> any any (msg:\"%s\"; flow:to_server; ", msg);
	fprintf(url_signature_file, "pcre:\"/%s/I\"; sid:%d;)\n", pcre, sig_id);
	fclose(url_signature_file);
}

struct cmd_create_result {
	cmdline_fixed_string_t create_db;
};

/*
	根据文件创建数据库
*/
static void
cmd_create_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	create_database(DEFAULT_TXT_INPUT);
}

cmdline_parse_token_string_t cmd_create_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_result, create_db, "create database");

cmdline_parse_inst_t cmd_create = {
	.f = cmd_create_parsed,  /* function to call */
	.data = NULL,          /* 2nd arg of func */
	.help_str = "Delete and create a new database",
	.tokens = {            /* token list, NULL terminated */
		(void *)&cmd_create_tok,
		NULL,
	},
};

struct cmd_update_result {
	cmdline_fixed_string_t commit_db;
	cmdline_fixed_string_t file_path;
};

static void
cmd_update_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_update_result *path_data = (struct cmd_update_result *)parsed_result;

	compile_and_load_signatures(path_data->file_path, DEFAULT_CDO_OUTPUT);
}

cmdline_parse_token_string_t cmd_commit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_update_result, commit_db, "commit database");

cmdline_parse_token_string_t cmd_path_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_update_result, file_path, NULL);

cmdline_parse_inst_t cmd_update = {
	.f = cmd_update_parsed,  /* function to call */
	.data = NULL,          /* 2nd arg of func */
	.help_str = "Update the DPI database in filepath - default is /tmp/signature.txt",
	.tokens = {            /* token list, NULL terminated */
		(void *)&cmd_commit_tok,
		(void *)&cmd_path_tok,
		NULL,
	},
};

struct cmd_filter_result {
	cmdline_fixed_string_t filter;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t msg;
	cmdline_fixed_string_t pcre;
};

static void
cmd_filter_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_filter_result *filter_data = (struct cmd_filter_result *)parsed_result;

	create_url_signature(DEFAULT_TXT_INPUT, global_sig_id, filter_data->msg, filter_data->pcre);
	DOCA_LOG_DBG("Created sig_id=%d", global_sig_id);
	global_sig_id++;
}

cmdline_parse_token_string_t cmd_filter_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, filter, "filter");

cmdline_parse_token_string_t cmd_http_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, proto, "http");
cmdline_parse_token_string_t cmd_msg_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, msg, NULL);
cmdline_parse_token_string_t cmd_pcre_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, pcre, NULL);


cmdline_parse_inst_t cmd_filter = {
	.f = cmd_filter_parsed,  /* function to call */
	.data = NULL,          /* 2nd arg of func */
	.help_str = "Filter URL - 3rd argument stand for the printed name and 4th for PCRE",
	.tokens = {            /* token list, NULL terminated */
		(void *)&cmd_filter_tok,
		(void *)&cmd_http_tok,
		(void *)&cmd_msg_tok,
		(void *)&cmd_pcre_tok,
		NULL,
	},
};

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,  /* function to call */
	.data = NULL,          /* 2nd arg of func */
	.help_str = "Exit application",
	.tokens = {            /* token list, NULL terminated */
		(void *)&cmd_quit_tok,
		NULL,
	},
};

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_filter,
	(cmdline_parse_inst_t *)&cmd_update,
	(cmdline_parse_inst_t *)&cmd_create,
	NULL,
};

static int
initiate_cmdline(char *cl_shell_output)
{
	int errno_output;
	struct cmdline *cl;

	global_sig_id = 1;
	cl = cmdline_stdin_new(main_ctx, cl_shell_output);

	if (cl == NULL)
		return -1;
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);
	if (remove(DEFAULT_CDO_OUTPUT) != 0) {
		errno_output = errno;
		DOCA_LOG_DBG("File removal failed : error %d", errno_output);
	}
	return 0;
}

static void
usage(const char *prog_name)
{
	printf("%s [EAL options] --\n"
		"-p or --print_match: Prints FID when matched in DPI engine\n"
		"-t or --connection_tracking: Control connection tracking flag\n"
		"-l or --log_level: Set the log level for the app ERR=0, DEBUG=3\n",
		prog_name);
}

/*
	获取参数，用参数来设置url_config
*/
static void
parse_input_args(int argc, char **argv, struct url_config *url_config)
{
	char **argvopt;
	int opt;
	int opt_idx;
	static struct option lgopts[] = {
		/* Show help. */
		{ "help",  no_argument, 0, ARG_HELP},
		/* Print on FID match */
		{ "print_match",  no_argument, 0, ARG_PRINT_MATCH},
		/* Activate connection tracking in the SFT */
		{ "connection_tracking",  no_argument, 0, ARG_CT},
		/* Log level */
		{ "log_level",  required_argument, 0, ARG_LOG_LEVEL},
		/* End of option. */
		{ 0, 0, 0, 0 }
	};

	static const char *shortopts = "hptl:";

	argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, shortopts, lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case ARG_PRINT_MATCH:
			url_config->print_on_match = true;
			break;
		case ARG_CT:
			url_config->ct = true;
			break;
		case ARG_LOG_LEVEL:
			doca_log_global_level_set(atoi(optarg));
			break;
		case ARG_HELP:
			usage("URL Filter app");
			break;
		default:
			fprintf(stderr, "Invalid option: %s\n", argv[optind]);
			usage("URL Filter example app");
			APP_EXIT("Invalid option\n");
			break;
		}
	}
}


static void
printf_signature(uint32_t sig_id, uint32_t fid)
{
	int ret;
	struct doca_dpi_sig_data sig_data;

	ret = doca_dpi_signature_get(dpi_ctx, sig_id, &sig_data);
	if (ret != 0)
		APP_EXIT("Failed to get signatures - error=%d\n", ret);
	DOCA_LOG_INFO("SIG ID: %u, URL MSG: %s, SFT_FID: %u", sig_id, sig_data.name, fid);
}

static enum dpi_worker_action
drop_on_match(int queue, const struct doca_dpi_result *result, uint32_t fid, void *user_data)
{
	uint32_t sig_id = result->info.sig_id;
	bool print_on_match = ((struct url_config *)user_data)->print_on_match;

	if (print_on_match)
		printf_signature(sig_id, fid);
	if (result->info.action == DOCA_DPI_SIG_ACTION_DROP)
		return DPI_WORKER_DROP;
	return DPI_WORKER_ALLOW;
}

/* 
	判断路径上的文件是否存在
*/
void
url_filter_init()
{
	if (access(COMPILER_PATH, F_OK) != 0)
		APP_EXIT("Compiler is missing - check PATH=%s\n", COMPILER_PATH);
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	int ret, err;
	unsigned int nb_ports, nb_queues = 0;
	struct doca_dpi_config_t doca_dpi_config = {
		/* Total number of DPI queues */
		.nb_queues = 0,
		/* Maximum job size in bytes for regex scan match */
		.max_sig_match_len = 5000,
		/* Max amount of FIDS per DPI queue */
		.max_packets_per_queue = 100000,
	};
	struct url_config url_config = {0};
	struct dpi_worker_attr url_filter_worker_attr = {0};
	struct rte_sft_error error;

	/* Initialize the Environment Abstraction Layer (EAL) */
	// dpdk初始化
	dpdk_init(&argc, &argv, &nb_queues, &nb_ports);

	/* Parse input arguments */
	// ？
	// 如果参数个数大于1，那么设置参数
	if (argc > 1)
		parse_input_args(argc, argv, &url_config);

	/* Check for required files */
	// 文件核对
	url_filter_init();

	/* Initialize mbuf and ports */
	// 初始化缓存和端口
	if (dpdk_ports_init(nb_ports, nb_queues) != 0)
		APP_EXIT("Ports allocation failed");

	/* Initialize SFT and RSS */
	// sft初始化
	dpdk_sft_init(url_config.ct, nb_queues, nb_ports);

	/* Configure regex device and queues */
	// dpi初始化
	doca_dpi_config.nb_queues = nb_queues;
	dpi_ctx = doca_dpi_init(&doca_dpi_config, &err);
	if (dpi_ctx == NULL)
		APP_EXIT("DPI init failed\n");

	/* Starting main process on all available cores */
	url_filter_worker_attr.dpi_on_match = drop_on_match;
	url_filter_worker_attr.user_data = (void *)&url_config;
	url_filter_worker_attr.dpi_ctx = dpi_ctx;
	dpi_worker_lcores_run(nb_queues, CLIENT_ID, url_filter_worker_attr);
	initiate_cmdline("URL FILTER>> ");

	/* End of application flow */
	dpi_worker_lcores_stop(dpi_ctx);

	flow_offload_query_counters();

	doca_dpi_destroy(dpi_ctx);
	ret = rte_sft_fini(&error);
	if (ret < 0)
		APP_EXIT("SFT fini failed, error=%d\n", ret);

	return 0;
}
