#include <string.h>
#include <stdio.h>

/* prototypes for commands */
int hash_main (int argc, char **argv);  /* hash.c */
int crypt_main (int argc, char **argv); /* crypt.c */
int rekey_main (int argc, char **argv); /* crypt.c */

int
main (int argc, char **argv)
{
  int result = 0;

  const char *cmd = "";         /* the command name */
  int (*cmd_func) (int, char **) = NULL;        /* the selected command */

  if (argc >= 2)
    {
      /* peel off the command, and shift up the rest of the args */
      cmd = argv[1];
      for (int i = 2; i < argc; ++i)
        argv[i - 1] = argv[i];
      --argc;
    }

  if (!strcmp (cmd, "hash"))
    cmd_func = &hash_main;
  else if (!strcmp (cmd, "crypt"))
    cmd_func = &crypt_main;
  else if (!strcmp (cmd, "rekey"))
    cmd_func = &rekey_main;
  /* more commands go here */

  /* print usage if we didn't find a command to run */
  if (cmd_func == NULL)
    {
      fputs ("Usage: spritz hash [-h] [-s size] [file1 file2 ...]\n"
             "       spritz crypt [-d] [-p pwd] [file]\n"
             "       spritz crypt -n [-p pwd] [file1 file2 ...]\n"
             "       spritz rekey [-o oldpwd] [-n newpwd] file1 file2 ...\n\n",
             stderr);
      return 1;
    }
  return (*cmd_func) (argc, argv);
}
