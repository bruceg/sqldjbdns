#ifndef SQL_H
#define SQL_H

void sql_connect(void);
void sql_exec(char* q);
unsigned sql_fetch(unsigned row, unsigned col, char** result);
unsigned sql_ntuples(void);

#endif
