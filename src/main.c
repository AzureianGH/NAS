#include "nas.h"
#include <getopt.h>

void print_version()
{
#ifdef _WIN32
    printf("nas [nas-win-x64] ntos(6.2025.1.0) - 1.00\n");
    printf("Copyright (C) 2025 Nathan's Compiler Collection\n");
    printf("This is free software; see the source for copying conditions.  There is NO\n");
    printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
#else
    printf("nas [nas-linux-x64] any-linux(6.2025.1.0) - 1.00\n");
    printf("Copyright (C) 2025 Nathan's Compiler Collection\n");
    printf("This is free software; see the source for copying conditions.  There is NO\n");
    printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\r");
#endif
}

void print_usage(const char *program_name)
{
    printf("Usage: %s [options] input_file -o output_file\n", program_name);
    printf("Options:\n");    printf("  -m, --mode <mode>      Assembly mode (16 or 32, default: 16)\n");
    printf("  -f, --format <format>  Output format (bin, hex, elf, default: bin)\n");
    printf("                         Note: elf format only available in 32-bit mode\n");
    printf("  -o, --output <file>    Output file\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help message\n");
    printf("  --version              Show version information\n");
    printf("\nExamples:\n");
    printf("  %s -m16 -f bin test/os.asm -o test/os.bin\n", program_name);
    printf("  %s --mode 16 --format hex input.asm -o output.hex\n", program_name);
}

int main(int argc, char *argv[])
{
    char *input_file = NULL;
    char *output_file = NULL;
    asm_mode_t mode = MODE_16BIT;
    output_format_t format = FORMAT_BIN;
    bool verbose = false;

    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"format", required_argument, 0, 'f'},
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 0},
        {0, 0, 0, 0}};

    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "m:f:o:vh", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'm':
            if (strcmp(optarg, "16") == 0)
            {
                mode = MODE_16BIT;
            }
            else if (strcmp(optarg, "32") == 0)
            {
                mode = MODE_32BIT;
            }
            else
            {
                fprintf(stderr, "Error: Invalid mode '%s'. Use 16 or 32.\n", optarg);
                return 1;
            }
            break;        case 'f':
            if (strcmp(optarg, "bin") == 0)
            {
                format = FORMAT_BIN;
            }
            else if (strcmp(optarg, "hex") == 0)
            {
                format = FORMAT_HEX;
            }
            else if (strcmp(optarg, "elf") == 0)
            {
                format = FORMAT_ELF;
            }
            else
            {
                fprintf(stderr, "Error: Invalid format '%s'. Use bin, hex, or elf.\n", optarg);
                return 1;
            }
            break;

        case 'o':
            output_file = optarg;
            break;

        case 'v':
            verbose = true;
            break;

        case 'h':
            print_usage(argv[0]);
            return 0;

        case 0:
            if (strcmp(long_options[option_index].name, "version") == 0)
            {
                print_version();
                return 0;
            }
            break;

        case '?':
            return 1;

        default:
            abort();
        }
    }

    // Get input file from remaining arguments
    if (optind < argc)
    {
        input_file = argv[optind];
    }    // Validate arguments
    if (!input_file)
    {
        fprintf(stderr, "Error: No input file specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!output_file)
    {
        fprintf(stderr, "Error: No output file specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Validate ELF format is only used with 32-bit mode
    if (format == FORMAT_ELF && mode != MODE_32BIT)
    {
        fprintf(stderr, "Error: ELF format (-f elf) is only available in 32-bit mode (-m 32).\n");
        return 1;
    }

    // Create assembler
    assembler_t *asm_ctx = assembler_create();
    if (!asm_ctx)
    {
        fprintf(stderr, "Error: Failed to create assembler.\n");
        return 1;
    }

    // Configure assembler
    assembler_set_cmdline_mode(asm_ctx, mode);
    assembler_set_format(asm_ctx, format);
    asm_ctx->verbose = verbose;    if (verbose)
    {
        printf("NAS - Nathan's Assembler\n");
        printf("Input file: %s\n", input_file);
        printf("Output file: %s\n", output_file);
        printf("Mode: %d-bit\n", mode);
        printf("Format: %s\n", format == FORMAT_BIN ? "binary" : (format == FORMAT_HEX ? "hex" : "elf"));
        printf("\n");
    }

    // Assemble the file
    bool success = assembler_assemble_file(asm_ctx, input_file, output_file);

    // Cleanup
    assembler_destroy(asm_ctx);

    if (!success)
    {
        fprintf(stderr, "Assembly failed.\n");
        return 1;
    }

    if (verbose)
    {
        printf("Assembly completed successfully.\n");
    }

    return 0;
}