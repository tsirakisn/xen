/*
 *  linux/arch/arm/lib/testclearbit.S
 *
 *  Copyright (C) 1995-1996 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "assembler.h"
#include "bitops.h"
                .text

testop	_test_and_clear_bit, bicne, strne
