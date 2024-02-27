#include "logger_api.h"
#include <stdint.h>
#include <stdarg.h>

uint8_t debug_lvl=0;

char* msg_log_fields[FIELDS_COUNT] = {
    [TIME] = "time",     [DATE] = "date", [CS_METHOD] = "cs-method",
    [CS_URI] = "cs_uri", [C_IP] = "c-ip", [SC_STATUS] = "sc-status",
    [S_IP] = "s-ip"};

char* methods[METHODS_COUNT] = {
    [GET] = "get",
    [UNSUPPORTED] = "unsupported",
};


void print_current_time();

char* get_method_name(Method m, char** methods)
{
       if ((int)m >= FIELDS_COUNT || (int)m < 0)
    {
        return NULL;
    }

    return (char*)methods[m]; 
}

char* get_msg_log_field_name(field_t field_type, char** fields)
{

    if ((int)field_type >= FIELDS_COUNT || (int)field_type < 0)
    {
        return NULL;
    }

    return (char*)fields[field_type];
}

void construct_msg_log_header(char* header_buf, size_t header_size,
                              float version, char** fields, uint8_t options)
{

    char* format_str = NULL;
    int nbytes = 0;
    int written = 0;

    format_str = "#Version: %.1f" CRLF;
    char version_buf[HDR_VERSION_LENGTH];
    sprintf(version_buf, format_str, version);

    char options_buf[HDR_OPTION_LENGTH * options];
    if (options > 0)
    {
        nbytes = 0;
        written = 0;

        if (options & DATE_OPTION)
        {
            format_str = "#Date: %F" CRLF;
            time_t t;
            struct tm* t_info;
            t = time(NULL);
            t_info = localtime(&t);
            nbytes = strftime(options_buf + written, HDR_OPTION_LENGTH,
                              format_str, t_info);
            written += nbytes;
        }

        if (options & SOFTWARE_OPTION)
        {
            char* software = "webserver/c";
            format_str = "#Software: %s" CRLF;
            nbytes = sprintf(options_buf + written, format_str, software);
            written += nbytes;
        }
    }

    char fields_buf[HDR_FIELDS_LENGTH];
    nbytes = sprintf(fields_buf, "#Fields: ");
    written = nbytes;
    format_str = "%s ";

    for (int i = 0; i < FIELDS_COUNT; i++)
    {
        if (i == FIELDS_COUNT - 1)
        {
            format_str = "%s" CRLF;
        }
        nbytes = sprintf(fields_buf + written, format_str,
                         get_msg_log_field_name((field_t)i, fields));
        written += nbytes;
    }

    /* header should look as following:
      version
       options
       fields
     */

    if (options > 0)
    {
        format_str = "%s%s%s";
        sprintf(header_buf, format_str, version_buf, options_buf, fields_buf);
    }
    else
    {
        format_str = "%s%s";
        sprintf(header_buf, format_str, version_buf, fields_buf);
    }
}

void msg_log(FILE* fp, char* msg, uint8_t options)
{
    fprintf(fp, "%s", msg);
}

int serialize_msg_log_entry(char* entry_buf, size_t entry_buf_size,
                             log_entry_config_t* msg_log_entry)
{

    char* format_str;
    char* terminating_char;
    int nbytes = 0;
    size_t written = 0;
    char date_buf[TS_BUF_LENGTH];
    char time_buf[TS_BUF_LENGTH];
    time_t t = time(NULL);
    struct tm* tp = localtime(&t);
    strftime(date_buf, TS_BUF_LENGTH, "%F", tp);
    strftime(time_buf, TS_BUF_LENGTH, "%H:%M:%S", tp);

    for (int i = 0; i < FIELDS_COUNT; ++i)
    {
	if(written > entry_buf_size)
	{
	    printf("not enough memory for log entry allocated\n");
	    return -1;
	}
        switch ((field_t)i)
        {
            case DATE:
                format_str = "%s";
                nbytes = sprintf(entry_buf + written, format_str,
                                date_buf);
                break;
            case TIME:
                format_str = "%s";
                nbytes = sprintf(entry_buf + written, format_str,
                                 time_buf);
                break;
            case CS_URI:
                format_str = "%s";
                nbytes = sprintf(entry_buf + written, format_str,
                                 msg_log_entry->cs_uri);
                break;
            case CS_METHOD:
                format_str = "%s";
		char* method= get_method_name(msg_log_entry->cs_method, methods);
		if(method == NULL)
		{
		    
		    return -1;
		}
                nbytes = sprintf(entry_buf + written, format_str,
                                 method);
                break;
            case S_IP:
                format_str = "%s";
                nbytes = sprintf(entry_buf + written, format_str,
                                 msg_log_entry->s_ip);
                break;
            case C_IP:
                format_str = "%s";
                nbytes = sprintf(entry_buf + written, format_str,
                                 msg_log_entry->c_ip);
                break;
            case SC_STATUS:
                format_str = "%i";
                nbytes = sprintf(entry_buf + written, format_str,
                                 msg_log_entry->sc_status);
                break;
            default:
                printf("undefined message log entry field [%s]\n",
                       get_msg_log_field_name((field_t)i, msg_log_fields));
                format_str = "%s";
                nbytes = sprintf(entry_buf + written, format_str, HYPHEN);

                break;
        }

        written += nbytes;
        terminating_char = (i == FIELDS_COUNT - 1) ? CRLF : SPACE;
        format_str = "%s";
        nbytes = sprintf(entry_buf + written, format_str, terminating_char);
        written += nbytes;
    }

    return 0;
}

void print_current_time()
{
    char time_buf[TS_BUF_LENGTH];
    time_t t = time(NULL);
    struct tm* tp = localtime(&t);
    strftime(time_buf, TS_BUF_LENGTH, "%F %H:%M:%S", tp);
    printf("%s ", time_buf);
}

void print_debug(log_lvl_t log_lvl, char* fmt, ...)
{
    if (log_lvl < 0 || log_lvl >= COUNT_LOG_LVL)
    {
        return;
    }
    
    if(debug_lvl < (uint8_t) log_lvl)
    {
	return;
    }

    if(log_lvl > NONE)
    {
	 print_current_time();
    }
    
    va_list args;
    va_start(args, fmt);
    switch (log_lvl)
    {
        case NONE:
            break;
        case ERROR:
	    printf("%sERROR: %s", ESC_COLOR_RED, ESC_COLOR_RESET);
            vprintf(fmt, args);
            break;
        case WARN:
   	    printf("%sWARN: %s", ESC_COLOR_YELLOW, ESC_COLOR_RESET);
            vprintf(fmt, args);
            break;
        case INFO:
            printf("%sINFO: %s", ESC_COLOR_GREEN, ESC_COLOR_RESET);
            vprintf(fmt, args);
            break;
        default:
            break;
    }
    va_end(args);
}
