//
// Created by akarner on 4/5/21.
//

#ifndef SIPLINE_PINGWORKER_H
#define SIPLINE_PINGWORKER_H

int doPost(int sock, ping_task_t* task);

int doGet(int sock, ping_task_t* task);

int prepareSocket(int *sock, ping_task_t *task);

int pingBackend(ping_task_t *task);

void *workerRoutine(void *args);

#endif //SIPLINE_PINGWORKER_H
