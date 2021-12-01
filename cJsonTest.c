#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "cJSON.h"

#define FILEPATH "./test.txt"
#define JSON_LOOP_FIELD 5

struct zn_rule_json {
	char operation[20];
	char event_type[20];
	char alarm_name[100];
	char alarm_level[10];
	char alarm_category[20];
	char link_region[20];
	char ips[200];
	char domains[200];
	char rule_content[512];
};

static int32_t get_file_size(const char *path)
{
    struct stat *statbuff = malloc(sizeof(struct stat));
    if (statbuff) {
        if (0 > stat(path, statbuff)) {
            free(statbuff);
            return -1;
        } else {
            int f_size = statbuff->st_size;
            free(statbuff);
            return f_size;
        }
    } else {
        return -1;
    }
}

void LoopOutput()
{
	for(int i = 0; i < 3; i++)
	{
		printf("--> i = %d\n", i);
	}
}

void OutputJson()
{
	cJSON *root = cJSON_CreateObject();
	cJSON *obj1 = cJSON_CreateObject();
	cJSON *obj2 = cJSON_CreateObject();
	
	cJSON_AddNumberToObject(root, "error_code", 9999);
	cJSON_AddStringToObject(root, "error_msg", "system inner error");

	{
		cJSON_AddItemToObject(root, "gw", obj1);
		cJSON_AddStringToObject(obj1, "name", "AAA1");
		cJSON_AddNumberToObject(obj1, "type", 11);
		cJSON_AddStringToObject(obj1, "info", "CCC1");

		cJSON *gw_version = cJSON_CreateObject();
		cJSON_AddItemToObject(obj1, "version", gw_version);
		cJSON_AddNumberToObject(gw_version, "ver_1", 10);
		cJSON_AddNumberToObject(gw_version, "ver_2", 11);
		cJSON_AddNumberToObject(gw_version, "ver_3", 12);
		cJSON_AddStringToObject(gw_version, "full1", "2021-12-01 18:30");
		cJSON_AddStringToObject(gw_version, "build_date1", "2021-12-01");
		cJSON_AddStringToObject(gw_version, "build_time1", "18:30");
	}

	{
		cJSON_AddItemToObject(root, "zk", obj2);
		cJSON_AddStringToObject(obj2, "name", "AAA1");
		cJSON_AddNumberToObject(obj2, "type", 11);
		cJSON_AddStringToObject(obj2, "info", "CCC1");

		cJSON *gw_version = cJSON_CreateObject();
		cJSON_AddItemToObject(obj2, "version", gw_version);
		cJSON_AddNumberToObject(gw_version, "ver_1", 10);
		cJSON_AddNumberToObject(gw_version, "ver_2", 11);
		cJSON_AddNumberToObject(gw_version, "ver_3", 12);
		cJSON_AddStringToObject(gw_version, "full1", "2021-12-01 18:30");
		cJSON_AddStringToObject(gw_version, "build_date1", "2021-12-01");
		cJSON_AddStringToObject(gw_version, "build_time1", "18:30");
	}

	char* json_str = cJSON_Print(root);
	printf("%s\n", json_str);
	free(json_str);

	char *json_str1 = cJSON_PrintUnformatted(root);
	printf("-------------------------------------------------\n");
	printf("%s\n", json_str1);
	free(json_str1);
}

int main(int argc, char* argv[])
{
	struct zn_rule_json stru_zn_rule;
	memset(&stru_zn_rule, 0, sizeof(struct zn_rule_json));

	int size = get_file_size(FILEPATH);
	FILE *file_fd = fopen(FILEPATH, "r");
    if (NULL == file_fd) {
		printf("open file error\n");
		return -1;
    }

	char *file_content = malloc(size);
    fread(file_content, 1, size, file_fd);
	fclose(file_fd);
	printf("-------------------------------------------------\n");
	printf("%s", file_content);
	printf("-------------------------------------------------\n");

	cJSON *zn_json = cJSON_Parse((char *)file_content);
    free(file_content);
	if (NULL == zn_json) {
		printf("parse json failed\n");
		return -1;
    }

	cJSON *oper = cJSON_GetObjectItemCaseSensitive(zn_json, "operation");
	if(cJSON_IsString(oper)) {
		strcpy(stru_zn_rule.operation, oper->valuestring);
	}

	cJSON *data_info = cJSON_GetObjectItem(zn_json, "data");
	cJSON *pAlarmName = cJSON_GetObjectItemCaseSensitive(data_info, "alarm_name");
	if(cJSON_IsString(pAlarmName)) {
		strcpy(stru_zn_rule.alarm_name, pAlarmName->valuestring);
	}

	cJSON *pEventType = cJSON_GetObjectItemCaseSensitive(data_info, "event_type_code");
	if(cJSON_IsString(pEventType)) {
		strcpy(stru_zn_rule.event_type, pEventType->valuestring);
	}

	cJSON *pLevel = cJSON_GetObjectItemCaseSensitive(data_info, "level");
	if(cJSON_IsString(pLevel)) {
		strcpy(stru_zn_rule.alarm_level, pLevel->valuestring);
	}

	cJSON *pAlarmCategory = cJSON_GetObjectItemCaseSensitive(data_info, "alarm_category");
	if(cJSON_IsString(pAlarmCategory)) {
		strcpy(stru_zn_rule.alarm_category, pAlarmCategory->valuestring);
	}

	cJSON *pLinkRegion = cJSON_GetObjectItemCaseSensitive(data_info, "link_region");
	if(cJSON_IsString(pLinkRegion)) {
		strcpy(stru_zn_rule.link_region, pLinkRegion->valuestring);
	}
	
	if(!strcmp(stru_zn_rule.event_type, "ip")) {
		cJSON *ips = cJSON_GetObjectItemCaseSensitive(data_info, "ips");
		if(cJSON_IsString(ips)) {
			strcpy(stru_zn_rule.ips, ips->valuestring);
		}
	} else if(!strcmp(stru_zn_rule.event_type, "domain")) {
		cJSON *domains = cJSON_GetObjectItemCaseSensitive(data_info, "domains");
		if(cJSON_IsString(domains)) {
			strcpy(stru_zn_rule.domains, domains->valuestring);
		}
	} else if(!strcmp(stru_zn_rule.event_type, "feature") || !strcmp(stru_zn_rule.event_type, "behavior")) {
		cJSON *ruleContent = cJSON_GetObjectItemCaseSensitive(data_info, "rule_content");
		if(cJSON_IsString(ruleContent)) {
			strcpy(stru_zn_rule.rule_content, ruleContent->valuestring);
		}
	}

	printf("string: %s\n", stru_zn_rule.operation);
	printf("string: %s\n", stru_zn_rule.alarm_name);
	printf("string: %s\n", stru_zn_rule.event_type);
	printf("string: %s\n", stru_zn_rule.alarm_level);
	printf("string: %s\n", stru_zn_rule.alarm_category);
	printf("string: %s\n", stru_zn_rule.link_region);
	if(strlen(stru_zn_rule.ips) > 0) {
		printf("string: %s\n", stru_zn_rule.ips);
	}
	if(strlen(stru_zn_rule.domains) > 0) {
		printf("string: %s\n", stru_zn_rule.domains);
	}
	if(strlen(stru_zn_rule.rule_content) > 0) {
		printf("string: %s\n", stru_zn_rule.rule_content);
	}
	printf("-------------------------------------------------\n");
    cJSON_Delete(zn_json);

	OutputJson();
	LoopOutput();
	return 0;
}


