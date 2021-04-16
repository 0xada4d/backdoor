void dump(const unsigned char *data_buffer, const unsigned int length)
{
    unsigned char byte;
    unsigned int i, j;

    for (i = 0; i < length; i++)
    {
        byte = data_buffer[i];
        printf("%02x ", byte);
        if (((i%16) == 15) || (i==length -1))
        {
            for (j = 0; j < 15-(i%16); j++)
                printf("   ");
            printf("| ");
            for (j=(i-(i%16)); j <= i; j++)
            {
                byte = data_buffer[j];
                if ((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

void fatal(const char * str)
{
    printf(str);
    printf("\n");
    exit(1);
}

