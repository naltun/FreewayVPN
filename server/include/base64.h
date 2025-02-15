/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef BASE64_H
#define BASE64_H

#include <sys/types.h>

int b64_ntop(u_char *src, size_t srclength, char *target, size_t targsize);
int b64_pton(const char *src, u_char *target, size_t targsize);

#endif /* BASE64_H */
