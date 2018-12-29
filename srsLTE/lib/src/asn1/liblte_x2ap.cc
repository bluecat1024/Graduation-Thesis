#include "srslte/asn1/liblte_x2ap.h"
# include <stdio.h>
# include <stdarg.h>
# include <math.h>

/*******************************************************************************
                              LOGGING
*******************************************************************************/

static log_handler_t log_handler;
static void *callback_ctx = NULL;

void liblte_x2ap_log_register_handler(void *ctx, log_handler_t handler) {
  log_handler  = handler;
  callback_ctx = ctx;
}

static void liblte_x2ap_log_print(const char *format, ...) {
  va_list   args;
  va_start(args, format);
  if (log_handler) {
    char *args_msg = NULL;
    if(vasprintf(&args_msg, format, args) > 0) {
      log_handler(callback_ctx, args_msg);
    }
    if (args_msg) {
      free(args_msg);
    }
  } else {
    vprintf(format, args);
  }
  va_end(args);
}

/*******************************************************************************
/* ProtocolIE Criticality ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_criticality(
  LIBLTE_X2AP_CRITICALITY_ENUM                                       *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 2);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_criticality(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CRITICALITY_ENUM                                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE local INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_local(
  LIBLTE_X2AP_LOCAL_STRUCT                                           *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->local
    // lb:0, ub:65535
    liblte_align_up_zero(ptr, 8);
    // Next line commented by ZY
    // liblte_value_2_bits(0, ptr, (2*8)-16);
    liblte_value_2_bits(ie->local, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_local(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_LOCAL_STRUCT                                           *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->local
    // lb:0, ub:65535
    liblte_align_up(ptr, 8);

    // Original version below:
    // ie->local = (uint16_t)liblte_bits_2_value(ptr, 2.0*8);
    // Modified to be the next line by ZY
    ie->local = (uint16_t)liblte_bits_2_value(ptr, 16);

    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE PrivateIE_ID CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_privateie_id(
  LIBLTE_X2AP_PRIVATEIE_ID_STRUCT                                    *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if (ie != NULL &&
      ptr != NULL)
  {
    // Choice type
    liblte_value_2_bits(ie->choice_type, ptr, 1);
    // Choice
    if (ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_LOCAL) {
      if (liblte_x2ap_pack_local(&ie->choice.local, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_GLOBAL) {
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_privateie_id(
    uint8_t **ptr,
    LIBLTE_X2AP_PRIVATEIE_ID_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if (ie != NULL &&
      ptr != NULL)
  {
    // Choice type
    ie->choice_type = (LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_ENUM)liblte_bits_2_value(ptr, 1);
    // Choice
    if (ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_LOCAL) {
      if (liblte_x2ap_unpack_local(ptr, &ie->choice.local) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_GLOBAL) {
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/* Do not need this for X2AP -- WT
/*******************************************************************************
/* ProtocolIE ProtocolExtensionID INTEGER
********************************************************************************
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolextensionid(
  LIBLTE_X2AP_PROTOCOLEXTENSIONID_STRUCT                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->ProtocolExtensionID
    // lb:0, ub:65535
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (2*8)-16);
    liblte_value_2_bits(ie->ProtocolExtensionID, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolextensionid(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLEXTENSIONID_STRUCT                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->ProtocolExtensionID
    // lb:0, ub:65535
    liblte_align_up(ptr, 8);
    ie->ProtocolExtensionID = (uint16_t)liblte_bits_2_value(ptr, 2.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
*/

 /*******************************************************************************
/* ProtocolIE TriggeringMessage ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_triggeringmessage(
  LIBLTE_X2AP_TRIGGERINGMESSAGE_ENUM                                 *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 2);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_triggeringmessage(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_TRIGGERINGMESSAGE_ENUM                                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_TRIGGERINGMESSAGE_ENUM)liblte_bits_2_value(ptr, 2);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE Presence ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_presence(
  LIBLTE_X2AP_PRESENCE_ENUM                                          *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 2);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_presence(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PRESENCE_ENUM                                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_PRESENCE_ENUM)liblte_bits_2_value(ptr, 2);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_ID INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_id(
  LIBLTE_X2AP_PROTOCOLIE_ID_STRUCT                                   *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->ProtocolIE_ID
    // lb:0, ub:65535
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (2*8)-16);
    liblte_value_2_bits(ie->ProtocolIE_ID, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_ID_STRUCT                                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->ProtocolIE_ID
    // lb:0, ub:65535
    liblte_align_up(ptr, 8);
    ie->ProtocolIE_ID = (uint16_t)liblte_bits_2_value(ptr, 2.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProcedureCode INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_procedurecode(
  LIBLTE_X2AP_PROCEDURECODE_STRUCT                                   *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->ProcedureCode
    // lb:0, ub:255
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (1*8)-8);
    liblte_value_2_bits(ie->ProcedureCode, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_procedurecode(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROCEDURECODE_STRUCT                                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->ProcedureCode
    // lb:0, ub:255
    liblte_align_up(ptr, 8);
    ie->ProcedureCode = (uint8_t)liblte_bits_2_value(ptr, 1.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_Field SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_field(
  LIBLTE_X2AP_PROTOCOLIE_FIELD_STRUCT                                *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_pack_protocolie_id(&ie->id, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
     // Enum - ie->criticality
    liblte_value_2_bits(ie->criticality, ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_field(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_FIELD_STRUCT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_unpack_protocolie_id(ptr, &ie->id) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
     // Enum - ie->criticality
    ie->criticality = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_SingleContainer SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_singlecontainer(
  LIBLTE_X2AP_PROTOCOLIE_SINGLECONTAINER_STRUCT                      *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_pack_protocolie_id(&ie->id, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
     // Enum - ie->criticality
    liblte_value_2_bits(ie->criticality, ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_singlecontainer(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_SINGLECONTAINER_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_unpack_protocolie_id(ptr, &ie->id) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
     // Enum - ie->criticality
    ie->criticality = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_Container DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:65535
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_container(
  LIBLTE_X2AP_PROTOCOLIE_CONTAINER_STRUCT                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_Container pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_protocolie_field(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_container(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_CONTAINER_STRUCT                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    ie->len = liblte_bits_2_value(ptr, 16) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_Container unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_field(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolExtensionField SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolextensionfield(
  LIBLTE_X2AP_PROTOCOLEXTENSIONFIELD_STRUCT                          *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_pack_protocolie_id(&ie->id, ptr) != LIBLTE_SUCCESS) { // changed by ZY
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
     // Enum - ie->criticality
    liblte_value_2_bits(ie->criticality, ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolextensionfield(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLEXTENSIONFIELD_STRUCT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_unpack_protocolie_id(ptr, &ie->id) != LIBLTE_SUCCESS) { // changed by ZY
      return LIBLTE_ERROR_DECODE_FAIL;
    }
     // Enum - ie->criticality
    ie->criticality = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolExtensionContainer DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:65535
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolextensioncontainer(
  LIBLTE_X2AP_PROTOCOLEXTENSIONCONTAINER_STRUCT                      *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolExtensionContainer pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_protocolextensionfield(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolextensioncontainer(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLEXTENSIONCONTAINER_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    ie->len = liblte_bits_2_value(ptr, 16) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolExtensionContainer unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolextensionfield(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_FieldPair SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_fieldpair(
  LIBLTE_X2AP_PROTOCOLIE_FIELDPAIR_STRUCT                            *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_pack_protocolie_id(&ie->id, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
     // Enum - ie->firstCriticality
    liblte_value_2_bits(ie->firstCriticality, ptr, 2);
     // Enum - ie->secondCriticality
    liblte_value_2_bits(ie->secondCriticality, ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_fieldpair(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_FIELDPAIR_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_unpack_protocolie_id(ptr, &ie->id) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
     // Enum - ie->firstCriticality
    ie->firstCriticality = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
     // Enum - ie->secondCriticality
    ie->secondCriticality = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_ContainerPair DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:0, ub:65535
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_containerpair(
  LIBLTE_X2AP_PROTOCOLIE_CONTAINERPAIR_STRUCT                        *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_ContainerPair pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-0, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_protocolie_fieldpair(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_containerpair(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_CONTAINERPAIR_STRUCT                        *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    ie->len = liblte_bits_2_value(ptr, 16) + 0;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_ContainerPair unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_fieldpair(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_ContainerList DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:None, ub:None
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_containerlist(
  LIBLTE_X2AP_PROTOCOLIE_CONTAINERLIST_STRUCT                    *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_ContainerList pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    if(ie->len < 128) {
      liblte_value_2_bits(0,       ptr, 1);
      liblte_value_2_bits(ie->len, ptr, 7);
    } else if(ie->len < 16383) {
      liblte_value_2_bits(1,       ptr, 1);
      liblte_value_2_bits(0,       ptr, 1);
      liblte_value_2_bits(ie->len, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of bits
      return err; // add by ZY, at least report error.
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_protocolie_container(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_containerlist(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_CONTAINERLIST_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    if (0 == liblte_bits_2_value(ptr, 1)) {
      ie->len = liblte_bits_2_value(ptr, 7);
    }
    else {
      if (0 == liblte_bits_2_value(ptr, 1)) {
        ie->len = liblte_bits_2_value(ptr, 14);
      }
      else {
        // FIXME: Unlikely to have more than 16K of bits
        return err; // add by ZY, at least report error.
      }
    }
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_ContainerPairList unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_container(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolIE_ContainerPairList DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:None, ub:None
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_containerpairlist(
  LIBLTE_X2AP_PROTOCOLIE_CONTAINERPAIRLIST_STRUCT                    *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_ContainerPairList pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    if(ie->len < 128) {
      liblte_value_2_bits(0,       ptr, 1);
      liblte_value_2_bits(ie->len, ptr, 7);
    } else if(ie->len < 16383) {
      liblte_value_2_bits(1,       ptr, 1);
      liblte_value_2_bits(0,       ptr, 1);
      liblte_value_2_bits(ie->len, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of bits
      return err; // add by ZY, at least report error.
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_protocolie_containerpair(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_containerpairlist(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PROTOCOLIE_CONTAINERPAIRLIST_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    if (0 == liblte_bits_2_value(ptr, 1)) {
      ie->len = liblte_bits_2_value(ptr, 7);
    }
    else {
      if (0 == liblte_bits_2_value(ptr, 1)) {
        ie->len = liblte_bits_2_value(ptr, 14);
      }
      else {
        // FIXME: Unlikely to have more than 16K of bits
        return err; // add by ZY, at least report error.
      }
    }
    if(ie->len > 32) {
      liblte_x2ap_log_print("ProtocolIE_ContainerPairList unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_containerpair(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE PrivateIE_Field SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_privateie_field(
  LIBLTE_X2AP_PRIVATEIE_FIELD_STRUCT                                 *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_pack_privateie_id(&ie->id, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
     // Enum - ie->criticality
    liblte_value_2_bits(ie->criticality, ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_privateie_field(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PRIVATEIE_FIELD_STRUCT                                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
     if(liblte_x2ap_unpack_privateie_id(ptr, &ie->id) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
     // Enum - ie->criticality
    ie->criticality = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE PrivateIE_Container DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:65535
LIBLTE_ERROR_ENUM liblte_x2ap_pack_privateie_container(
  LIBLTE_X2AP_PRIVATEIE_CONTAINER_STRUCT                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("PrivateIE_Container pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_privateie_field(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_privateie_container(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PRIVATEIE_CONTAINER_STRUCT                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    ie->len = liblte_bits_2_value(ptr, 16) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_x2ap_log_print("PrivateIE_Container unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_privateie_field(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE DL_ABS_status INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_dl_abs_status(
  LIBLTE_X2AP_DL_ABS_STATUS_STRUCT                                   *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->DL_ABS_Status, ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_dl_abs_status(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_DL_ABS_STATUS_STRUCT                                   *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->DL_ABS_Status = (uint32_t)liblte_bits_2_value(ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE BitRate INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_bitrate(
  LIBLTE_X2AP_BITRATE_STRUCT                                         *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->BitRate
    // lb:0, ub:10000000000
    // Range > 65536 - encoded based on value
    {
      uint32_t n_bits   = floor(log2(ie->BitRate-0)+1);
      uint32_t n_octets = (n_bits+7)/8;
      liblte_value_2_bits(n_octets-1, ptr, 3);
      liblte_align_up_zero(ptr, 8);
      liblte_value_2_bits(0, ptr, (n_octets*8)-n_bits);
      liblte_value_2_bits(ie->BitRate-0, ptr, n_bits);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_bitrate(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_BITRATE_STRUCT                                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->BitRate
    // lb:0, ub:10000000000
    // Range > 65536 - encoded based on value
    {
      uint32_t n_octets = liblte_bits_2_value(ptr, 3) + 1;
      liblte_align_up(ptr, 8);
      ie->BitRate = liblte_bits_2_value(ptr, n_octets*8) + 0;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE CapacityValue INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_capacityvalue(
  LIBLTE_X2AP_CAPACITYVALUE_STRUCT                                   *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->CapacityValue, ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_capacityvalue(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CAPACITYVALUE_STRUCT                                   *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->CapacityValue = (uint32_t)liblte_bits_2_value(ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE CellCapacityClassValue INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellcapacityclassvalue(
  LIBLTE_X2AP_CELLCAPACITYCLASSVALUE_STRUCT                                   *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->CellCapacityClassValue, ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellcapacityclassvalue(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLCAPACITYCLASSVALUE_STRUCT                                   *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->CellCapacityClassValue = (uint32_t)liblte_bits_2_value(ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE DL_GBR_PRB_usage INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_dl_gbr_prb_usage(
  LIBLTE_X2AP_DL_GBR_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->DL_GBR_PRB_usage, ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_dl_gbr_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_DL_GBR_PRB_USAGE_STRUCT                            *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->DL_GBR_PRB_usage = (uint16_t)liblte_bits_2_value(ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE DL_non_GBR_PRB_usage INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_dl_non_gbr_prb_usage(
  LIBLTE_X2AP_DL_NON_GBR_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->DL_non_GBR_PRB_usage, ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_dl_non_gbr_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_DL_NON_GBR_PRB_USAGE_STRUCT                            *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->DL_non_GBR_PRB_usage = (uint16_t)liblte_bits_2_value(ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE DL_Total_PRB_usage INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_dl_total_prb_usage(
  LIBLTE_X2AP_DL_TOTAL_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->DL_Total_PRB_usage, ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_dl_total_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_DL_TOTAL_PRB_USAGE_STRUCT                            *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->DL_Total_PRB_usage = (uint16_t)liblte_bits_2_value(ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE EARFCN INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_earfcn(
  LIBLTE_X2AP_EARFCN_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->EARFCN, ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_earfcn(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_EARFCN_STRUCT                            *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->EARFCN = (uint16_t)liblte_bits_2_value(ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE EARFCNExtension INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_earfcnextension(
  LIBLTE_X2AP_EARFCNEXTENSION_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	// liblte_value_2_bits(ie->EARFCNExtension, ptr, 16); changed by ZY
    liblte_value_2_bits(ie->EARFCNExtension, ptr, 32);

		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_earfcnextension(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_EARFCNEXTENSION_STRUCT                            *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		// ie->EARFCNExtension = (uint16_t)liblte_bits_2_value(ptr, 16); changed by ZY
    ie->EARFCNExtension = (uint16_t)liblte_bits_2_value(ptr, 32);

		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE E_RAB_ID INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_e_rab_id(
  LIBLTE_X2AP_E_RAB_ID_STRUCT                                        *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->E_RAB_ID
    // lb:0, ub:15
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ie->E_RAB_ID error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->E_RAB_ID, ptr, 4);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_e_rab_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_E_RAB_ID_STRUCT                                        *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->E_RAB_ID
    // lb:0, ub:15
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ie->E_RAB_ID error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->E_RAB_ID = (uint8_t)liblte_bits_2_value(ptr, 4);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE FreqBandIndicator INTEGER
********************************************************************************/

 LIBLTE_ERROR_ENUM liblte_x2ap_pack_freqbandindicator(
  LIBLTE_X2AP_FREQBANDINDICATOR_STRUCT                                       *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
	 	liblte_value_2_bits(ie->FreqBandIndicator, ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_freqbandindicator(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_FREQBANDINDICATOR_STRUCT                                       *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ptr != NULL && ie != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->FreqBandIndicator = (uint32_t)liblte_bits_2_value(ptr, 32);
		err = LIBLTE_SUCCESS;
	}
	return err;
}
 /*******************************************************************************
/* ProtocolIE HFN INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_hfn(
  LIBLTE_X2AP_HFN_STRUCT                                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->HFN
    // lb:0, ub:1048575
    // Range > 65536 - encoded based on value
    {
      uint32_t n_bits   = floor(log2(ie->HFN-0)+1);
      uint32_t n_octets = (n_bits+7)/8;
      liblte_value_2_bits(n_octets-1, ptr, 2);
      liblte_align_up_zero(ptr, 8);
      liblte_value_2_bits(0, ptr, (n_octets*8)-n_bits);
      liblte_value_2_bits(ie->HFN-0, ptr, n_bits);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_hfn(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_HFN_STRUCT                                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->HFN
    // lb:0, ub:1048575
    // Range > 65536 - encoded based on value
    {
      uint32_t n_octets = liblte_bits_2_value(ptr, 2) + 1;
      liblte_align_up(ptr, 8);
      ie->HFN = liblte_bits_2_value(ptr, n_octets*8) + 0;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE HFNModified INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_hfnmodified(
  LIBLTE_X2AP_HFNMODIFIED_STRUCT                                     *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->HFNModified
    // lb:0, ub:131071
    // Range > 65536 - encoded based on value
    {
      uint32_t n_bits   = floor(log2(ie->HFNModified-0)+1);
      uint32_t n_octets = (n_bits+7)/8;
      liblte_value_2_bits(n_octets-1, ptr, 2);
      liblte_align_up_zero(ptr, 8);
      liblte_value_2_bits(0, ptr, (n_octets*8)-n_bits);
      liblte_value_2_bits(ie->HFNModified-0, ptr, n_bits);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_hfnmodified(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_HFNMODIFIED_STRUCT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->HFNModified
    // lb:0, ub:131071
    // Range > 65536 - encoded based on value
    {
      uint32_t n_octets = liblte_bits_2_value(ptr, 2) + 1;
      liblte_align_up(ptr, 8);
      ie->HFNModified = liblte_bits_2_value(ptr, n_octets*8) + 0;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

 /*******************************************************************************
/* ProtocolIE Measurement_ID INTEGER
********************************************************************************/

 LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurement_id(
  LIBLTE_X2AP_MEASUREMENT_ID_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Measurement_ID
    // lb:0, ub:4095
    {
      liblte_align_up_zero(ptr, 8);
      liblte_value_2_bits(ie->Measurement_ID, ptr, 32);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurement_id(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MEASUREMENT_ID_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Measurement_ID
    // lb:0, ub:4095
    {
      liblte_align_up(ptr, 8);
      ie->Measurement_ID = liblte_bits_2_value(ptr, 32);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

	
/*******************************************************************************
/* ProtocolIE nextHopChainingCount INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_nexthopchainingcount(
  LIBLTE_X2AP_NEXTHOPCHAININGCOUNT_STRUCT                            *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->nextHopChainingCount
    // lb:0, ub:7
    liblte_value_2_bits(ie->NextHopChainingCount, ptr, 3);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_nexthopchainingcount(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_NEXTHOPCHAININGCOUNT_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->nextHopChainingCount
    // lb:0, ub:7
    ie->NextHopChainingCount = (uint8_t)liblte_bits_2_value(ptr, 3);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE PDCP_SN INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_pdcp_sn(
  LIBLTE_X2AP_PDCP_SN_STRUCT                                         *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->PDCP_SN
    // lb:0, ub:4095
    liblte_align_up_zero(ptr, 8);
    // liblte_value_2_bits(0, ptr, (1*8)-12); BUG! Comment out by ZY. S1AP is also buggy!
    liblte_value_2_bits(ie->PDCP_SN, ptr, 12);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_pdcp_sn(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PDCP_SN_STRUCT                                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->PDCP_SN
    // lb:0, ub:4095
    liblte_align_up(ptr, 8);
    ie->PDCP_SN = (uint16_t)liblte_bits_2_value(ptr, 1.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE PDCP_SNExtended INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_pdcp_snextended(
  LIBLTE_X2AP_PDCP_SNEXTENDED_STRUCT                                 *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->PDCP_SNExtended
    // lb:0, ub:32767
    liblte_align_up_zero(ptr, 8);
    // liblte_value_2_bits(0, ptr, (1*8)-15); BUG! Comment out by ZY. S1AP is also buggy!
    liblte_value_2_bits(ie->PDCP_SNExtended, ptr, 15);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_pdcp_snextended(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PDCP_SNEXTENDED_STRUCT                                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->PDCP_SNExtended
    // lb:0, ub:32767
    liblte_align_up(ptr, 8);
    ie->PDCP_SNExtended = (uint16_t)liblte_bits_2_value(ptr, 15);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE PCI INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_pci(
  LIBLTE_X2AP_PCI_STRUCT                                   *ie,
  uint8_t                                                     **ptr)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up_zero(ptr, 8);
		liblte_value_2_bits(ie->PCI, ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	 return err;
}
	 
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_pci(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_PCI_STRUCT                                   *ie)
{
	LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
	if(ie != NULL && ptr != NULL)
	{
		liblte_align_up(ptr, 8);
		ie->PCI = (uint16_t)liblte_bits_2_value(ptr, 16);
		err = LIBLTE_SUCCESS;
	}
	 return err;
}

 /*******************************************************************************
/* ProtocolIE PriorityLevel INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_prioritylevel(
  LIBLTE_X2AP_PRIORITYLEVEL_STRUCT                                   *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->PriorityLevel
    // lb:0, ub:15
    liblte_value_2_bits(ie->PriorityLevel, ptr, 4);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_prioritylevel(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PRIORITYLEVEL_STRUCT                                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->PriorityLevel
    // lb:0, ub:15
    ie->PriorityLevel = (uint8_t)liblte_bits_2_value(ptr, 4);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE QCI INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_qci(
  LIBLTE_X2AP_QCI_STRUCT                                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->QCI
    // lb:0, ub:255
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (1*8)-8);
    liblte_value_2_bits(ie->QCI, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_qci(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_QCI_STRUCT                                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->QCI
    // lb:0, ub:255
    liblte_align_up(ptr, 8);
    ie->QCI = (uint8_t)liblte_bits_2_value(ptr, 1.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

 /*******************************************************************************
/* ProtocolIE RadioframeAllocationOffset INTEGER
********************************************************************************/

 LIBLTE_ERROR_ENUM liblte_x2ap_pack_radioframeallocationoffset(
  LIBLTE_X2AP_RADIOFRAMEALLOCATIONOFFSET_STRUCT                                       *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->RadioframeAllocationOffset
    // lb:0, ub:7
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (1*8)-8);
    liblte_value_2_bits(ie->RadioframeAllocationOffset, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_radioframeallocationoffset(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_RADIOFRAMEALLOCATIONOFFSET_STRUCT                                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->RadioframeAllocationOffset
    // lb:0, ub:7
    liblte_align_up(ptr, 8);
    ie->RadioframeAllocationOffset = (uint8_t)liblte_bits_2_value(ptr, 1.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

 /*******************************************************************************
/* ProtocolIE subscriberProfileIDforRFP INTEGER
********************************************************************************/
 LIBLTE_ERROR_ENUM liblte_x2ap_pack_subscribeprofileidforrfp(
  LIBLTE_X2AP_SUBSCRIBERPROFILEIDFORRFP_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->SubscribeProfileIDforRFP
    // lb:1, ub:256
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (1*8)-8);
    liblte_value_2_bits(ie->SubscribeProfileIDforRFP, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_subscribeprofileidforrfp(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SUBSCRIBERPROFILEIDFORRFP_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->SubscribeProfileIDforRFP
    // lb:1, ub:256
    liblte_align_up(ptr, 8);
    ie->SubscribeProfileIDforRFP = (uint8_t)liblte_bits_2_value(ptr, 1.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

 /*******************************************************************************
/* ProtocolIE Threshold_RSRP INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_threshold_rsrp(
  LIBLTE_X2AP_THRESHOLD_RSRP_STRUCT                                  *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Threshold_RSRP
    // lb:0, ub:97
    liblte_value_2_bits(ie->Threshold_RSRP, ptr, 7);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_threshold_rsrp(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_THRESHOLD_RSRP_STRUCT                                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Threshold_RSRP
    // lb:0, ub:97
    ie->Threshold_RSRP = (uint8_t)liblte_bits_2_value(ptr, 7);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE Threshold_RSRQ INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_threshold_rsrq(
  LIBLTE_X2AP_THRESHOLD_RSRQ_STRUCT                                  *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Threshold_RSRQ
    // lb:0, ub:34
    liblte_value_2_bits(ie->Threshold_RSRQ, ptr, 6);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_threshold_rsrq(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_THRESHOLD_RSRQ_STRUCT                                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Threshold_RSRQ
    // lb:0, ub:34
    ie->Threshold_RSRQ = (uint8_t)liblte_bits_2_value(ptr, 6);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE Time_UE_StayedInCell INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_time_ue_stayedincell(
  LIBLTE_X2AP_TIME_UE_STAYEDINCELL_STRUCT                            *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Time_UE_StayedInCell
    // lb:0, ub:4095
    liblte_align_up_zero(ptr, 8);
    // liblte_value_2_bits(0, ptr, (1*8)-12); BUG! Comment out by ZY. S1AP is also buggy.
    liblte_value_2_bits(ie->Time_UE_StayedInCell, ptr, 12);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_time_ue_stayedincell(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_TIME_UE_STAYEDINCELL_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Time_UE_StayedInCell
    // lb:0, ub:4095
    liblte_align_up(ptr, 8);
    ie->Time_UE_StayedInCell = (uint16_t)liblte_bits_2_value(ptr, 1.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE Time_UE_StayedInCell_EnhancedGranularity INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_time_ue_stayedincell_enhancedgranularity(
  LIBLTE_X2AP_TIME_UE_STAYEDINCELL_ENHANCEDGRANULARITY_STRUCT        *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Time_UE_StayedInCell_EnhancedGranularity
    // lb:0, ub:40950
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(0, ptr, (2*8)-16);
    liblte_value_2_bits(ie->Time_UE_StayedInCell_EnhancedGranularity, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_time_ue_stayedincell_enhancedgranularity(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_TIME_UE_STAYEDINCELL_ENHANCEDGRANULARITY_STRUCT        *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->Time_UE_StayedInCell_EnhancedGranularity
    // lb:0, ub:40950
    liblte_align_up(ptr, 8);
    ie->Time_UE_StayedInCell_EnhancedGranularity = (uint16_t)liblte_bits_2_value(ptr, 2.0*8);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UE_S1AP_ID INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ue_s1ap_id(
  LIBLTE_X2AP_UE_S1AP_ID_STRUCT                  *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UE_S1AP_ID
    // lb:0, ub:4294967295
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(ie->UE_S1AP_ID, ptr, 32);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ue_s1ap_id(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UE_S1AP_ID_STRUCT                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UE_S1AP_ID
    // lb:0, ub:4294967295
    liblte_align_up(ptr, 8);
    ie->UE_S1AP_ID = (uint32_t)liblte_bits_2_value(ptr, 32);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UE_X2AP_ID INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ue_x2ap_id(
  LIBLTE_X2AP_UE_X2AP_ID_STRUCT                  *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UE_X2AP_ID
    // lb:0, ub:4095
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(ie->UE_X2AP_ID, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ue_x2ap_id(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UE_X2AP_ID_STRUCT                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UE_X2AP_ID
    // lb:0, ub:4095
    liblte_align_up(ptr, 8);
    ie->UE_X2AP_ID = (uint16_t)liblte_bits_2_value(ptr, 16);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UL_GBR_PRB_usage INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_gbr_prb_usage(
  LIBLTE_X2AP_UL_GBR_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UL_GBR_PRB_usage
    // lb:0, ub:100
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(ie->UL_GBR_PRB_usage, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_gbr_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_GBR_PRB_USAGE_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UL_GBR_PRB_usage
    // lb:0, ub:100
    liblte_align_up(ptr, 8);
    ie->UL_GBR_PRB_usage = (uint16_t)liblte_bits_2_value(ptr, 16);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UL_non_GBR_PRB_usage INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_non_gbr_prb_usage(
  LIBLTE_X2AP_UL_NON_GBR_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UL_non_GBR_PRB_usage
    // lb:0, ub:100
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(ie->UL_non_GBR_PRB_usage, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_non_gbr_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_NON_GBR_PRB_USAGE_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UL_non_GBR_PRB_usage
    // lb:0, ub:100
    liblte_align_up(ptr, 8);
    ie->UL_non_GBR_PRB_usage = (uint16_t)liblte_bits_2_value(ptr, 16);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UL_Total_PRB_usage INTEGER
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_total_prb_usage(
  LIBLTE_X2AP_UL_TOTAL_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UL_Total_PRB_usage
    // lb:0, ub:100
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(ie->UL_Total_PRB_usage, ptr, 16);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_total_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_TOTAL_PRB_USAGE_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    // Integer - ie->UL_Total_PRB_usage
    // lb:0, ub:100
    liblte_align_up(ptr, 8);
    ie->UL_Total_PRB_usage = (uint16_t)liblte_bits_2_value(ptr, 16);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CRNTI STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_crnti(
  LIBLTE_X2AP_CRNTI_STRUCT                               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    for (uint32_t i = 0; i < LIBLTE_X2AP_CRNTI_BIT_STRING_LEN; ++i)
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    err = LIBLTE_SUCCESS;
    liblte_align_up_zero(ptr, 8);
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_crnti(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CRNTI_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    for (uint32_t i = 0; i < LIBLTE_X2AP_CRNTI_BIT_STRING_LEN; ++i)
      ie->buffer[i] = (uint8_t)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CSG_Id STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_csg_id(
  LIBLTE_X2AP_CSG_ID_STRUCT                                          *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - CSG-Id
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_CSG_ID_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_csg_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CSG_ID_STRUCT                                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - CSG-Id
    liblte_align_up(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_CSG_ID_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE macroENB_ID STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_macroenb_id(
  LIBLTE_X2AP_MACROENB_ID_STRUCT                                     *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - macroENB-ID
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MACROENB_ID_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_macroenb_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MACROENB_ID_STRUCT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - macroENB-ID
    liblte_align_up(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MACROENB_ID_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE homeENB_ID STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_homeenb_id(
  LIBLTE_X2AP_HOMEENB_ID_STRUCT                                      *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - homeENB-ID
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_HOMEENB_ID_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_homeenb_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_HOMEENB_ID_STRUCT                                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - homeENB-ID
    liblte_align_up(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_HOMEENB_ID_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE EncryptionAlgorithms STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_encryptionalgorithms(
  LIBLTE_X2AP_ENCRYPTIONALGORITHMS_STRUCT                            *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - EncryptionAlgorithms
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("EncryptionAlgorithms error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_ENCRYPTIONALGORITHMS_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_encryptionalgorithms(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_ENCRYPTIONALGORITHMS_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - EncryptionAlgorithms
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("EncryptionAlgorithms error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_ENCRYPTIONALGORITHMS_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE EUTRANCellIdentifier STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_eutrancellidentifier(
  LIBLTE_X2AP_EUTRANCELLIDENTIFIER_STRUCT                               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - EUTRANCellIdentifier
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_EUTRANCELLIDENTIFIER_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_eutrancellidentifier(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_EUTRANCELLIDENTIFIER_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - EUTRANCellIdentifier
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_EUTRANCELLIDENTIFIER_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Fourframes STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_fourframes(
  LIBLTE_X2AP_FOURFRAMES_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - Fourframes
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_FOURFRAMES_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_fourframes(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_FOURFRAMES_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - Fourframes
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_FOURFRAMES_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE IntegrityProtectionAlgorithms STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_integrityprotectionalgorithms(
  LIBLTE_X2AP_INTEGRITYPROTECTIONALGORITHMS_STRUCT                   *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - IntegrityProtectionAlgorithms
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("IntegrityProtectionAlgorithms error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_INTEGRITYPROTECTIONALGORITHMS_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_integrityprotectionalgorithms(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_INTEGRITYPROTECTIONALGORITHMS_STRUCT                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - IntegrityProtectionAlgorithms
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("IntegrityProtectionAlgorithms error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_INTEGRITYPROTECTIONALGORITHMS_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE InterfacesToTrace STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_interfacestotrace(
  LIBLTE_X2AP_INTERFACESTOTRACE_STRUCT                               *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - InterfacesToTrace
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_INTERFACESTOTRACE_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_interfacestotrace(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_INTERFACESTOTRACE_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - InterfacesToTrace
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_INTERFACESTOTRACE_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Key_eNodeB_Star STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_key_enodeb_star(
  LIBLTE_X2AP_KEY_ENODEB_STAR_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - Key_eNodeB_Star
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_KEY_ENODEB_STAR_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_key_enodeb_star(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_KEY_ENODEB_STAR_STRUCT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - Key_eNodeB_Star
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_KEY_ENODEB_STAR_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE MDT_Location_Info STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mdt_location_info(
  LIBLTE_X2AP_MDT_LOCATION_INFO_STRUCT                               *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - MDT-Location-Info
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MDT_LOCATION_INFO_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mdt_location_info(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MDT_LOCATION_INFO_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - MDT-Location-Info
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MDT_LOCATION_INFO_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MeasurementsToActivate STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementstoactivate(
  LIBLTE_X2AP_MEASUREMENTSTOACTIVATE_STRUCT                          *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - MeasurementsToActivate
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MEASUREMENTSTOACTIVATE_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementstoactivate(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MEASUREMENTSTOACTIVATE_STRUCT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - MeasurementsToActivate
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MEASUREMENTSTOACTIVATE_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Oneframe STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_oneframe(
  LIBLTE_X2AP_ONEFRAME_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - macroENB-ID
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_ONEFRAME_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_oneframe(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ONEFRAME_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - macroENB-ID
    liblte_align_up(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_ONEFRAME_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE ReceiveStatusofULPDCPSDUs STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_receivestatusofulpdcpsdus(
  LIBLTE_X2AP_RECEIVESTATUSOFULPDCPSDUS_STRUCT                       *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - ReceiveStatusofULPDCPSDUs
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_RECEIVESTATUSOFULPDCPSDUS_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_receivestatusofulpdcpsdus(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_RECEIVESTATUSOFULPDCPSDUS_STRUCT                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - ReceiveStatusofULPDCPSDUs
    liblte_align_up(ptr, 8);
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_RECEIVESTATUSOFULPDCPSDUS_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ReceiveStatusOfULPDCPSDUsExtended DYNAMIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_receivestatusofulpdcpsdusextended(
  LIBLTE_X2AP_RECEIVESTATUSOFULPDCPSDUSEXTENDED_STRUCT               *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - ReceiveStatusOfULPDCPSDUsExtended
    // lb:1, ub:16384
    // Length
    liblte_value_2_bits(ie->n_bits-1, ptr, 14);
    liblte_align_up_zero(ptr, 8);
    
    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_receivestatusofulpdcpsdusextended(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_RECEIVESTATUSOFULPDCPSDUSEXTENDED_STRUCT               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - ReceiveStatusOfULPDCPSDUsExtended
    // lb:1, ub:16384
    // Length
    ie->n_bits = liblte_bits_2_value(ptr, 14) + 1;
    liblte_align_up(ptr, 8);

    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ReportCharateristics STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_reportcharacteristics(
  LIBLTE_X2AP_REPORTCHARACTERISTICS_STRUCT                     *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - ReportCharateristics
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_REPORTCHARATERISTICS_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_reportcharacteristics(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REPORTCHARACTERISTICS_STRUCT                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - ReportCharateristics
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_REPORTCHARATERISTICS_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ShortMAC_I STATIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_shortmac_i(
  LIBLTE_X2AP_SHORTMAC_I_STRUCT                       *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - ShortMAC_I
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_SHORTMAC_I_BIT_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_shortmac_i(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SHORTMAC_I_STRUCT                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static bit string - ShortMAC_I
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_SHORTMAC_I_BIT_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE TraceCollectionEntityIPAddress DYNAMIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_tracecollectionentityipaddress(
  LIBLTE_X2AP_TRACECOLLECTIONENTITYIPADDRESS_STRUCT                     *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - TransportLayerAddress
    // lb:1, ub:160
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TraceCollectionEntityIPAddress error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Length
    liblte_value_2_bits(ie->n_bits-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    
    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_tracecollectionentityipaddress(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TRACECOLLECTIONENTITYIPADDRESS_STRUCT                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - TransportLayerAddress
    // lb:1, ub:160
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TraceCollectionEntityIPAddress error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Length
    ie->n_bits = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);

    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE TransportLayerAddress DYNAMIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_transportlayeraddress(
  LIBLTE_X2AP_TRANSPORTLAYERADDRESS_STRUCT                           *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - TransportLayerAddress
    // lb:1, ub:160
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TransportLayerAddress error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Length
    liblte_value_2_bits(ie->n_bits-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    
    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_transportlayeraddress(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_TRANSPORTLAYERADDRESS_STRUCT                           *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - TransportLayerAddress
    // lb:1, ub:160
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TransportLayerAddress error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Length
    ie->n_bits = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);

    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UL_HighInterferenceIndication DYNAMIC BIT STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_highinterferenceindication(
  LIBLTE_X2AP_UL_HIGHINTERFERENCEINDICATION_STRUCT                               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - UL_HighInterferenceIndication
    // lb:1, ub:110
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("UL_HighInterferenceIndication error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Length
    liblte_value_2_bits(ie->n_bits-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    
    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 1);
    }
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_highinterferenceindication(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_HIGHINTERFERENCEINDICATION_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic bit string - UL_HighInterferenceIndication
    // lb:1, ub:110
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("UL_HighInterferenceIndication error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Length
    ie->n_bits = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);

    // Bits
    uint32_t i;
    for(i=0;i<ie->n_bits;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 1);
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/* Octet String */

/*******************************************************************************
/* ProtocolIE TBCD_STRING STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_tbcd_string(
  LIBLTE_X2AP_TBCD_STRING_STRUCT                                     *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - TBCD-STRING
    if(LIBLTE_X2AP_TBCD_STRING_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_TBCD_STRING_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_tbcd_string(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_TBCD_STRING_STRUCT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - TBCD-STRING
    if(LIBLTE_X2AP_TBCD_STRING_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_TBCD_STRING_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE EUTRANTraceID STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_eutrantraceid(
  LIBLTE_X2AP_EUTRANTRACEID_STRUCT                           *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - EUTRANTraceID
    if(LIBLTE_X2AP_EUTRANTRACEID_OCTET_STRING_LEN > 2) { // Do what S1AP do. Not sure if alignment is necessary.
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_EUTRANTRACEID_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_eutrantraceid(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_EUTRANTRACEID_STRUCT                           *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - EUTRANTraceID
    if(LIBLTE_X2AP_EUTRANTRACEID_OCTET_STRING_LEN > 2) { // Do what S1AP do. Not sure if alignment is necessary.
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_EUTRANTRACEID_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE GTP_TEI STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_gtp_tei(
  LIBLTE_X2AP_GTP_TEI_STRUCT                                        *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - GTP-TEI
    if(LIBLTE_X2AP_GTP_TEI_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_GTP_TEI_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_gtp_tei(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_GTP_TEI_STRUCT                                        *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - GTP-TEI
    if(LIBLTE_X2AP_GTP_TEI_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_GTP_TEI_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE LAC STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_lac(
  LIBLTE_X2AP_LAC_STRUCT                                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - LAC
    if(LIBLTE_X2AP_LAC_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_LAC_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_lac(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_LAC_STRUCT                                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - LAC
    if(LIBLTE_X2AP_LAC_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_LAC_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE LastVisitedUTRANCellInformation DYNAMIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_lastvisitedutrancellinformation(
  LIBLTE_X2AP_LASTVISITEDUTRANCELLINFORMATION_STRUCT                 *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - LastVisitedUTRANCellInformation
    // Length
    if(ie->n_octets < 128) {
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 7);
    } else if(ie->n_octets < 16383) {
      liblte_value_2_bits(1,            ptr, 1);
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
      return err; // At least return error. By ZY.
    }
    
    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_lastvisitedutrancellinformation(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_LASTVISITEDUTRANCELLINFORMATION_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - LastVisitedUTRANCellInformation
    // Length
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->n_octets = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->n_octets = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
      }
    }

    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MME_Group_ID STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mme_group_id(
  LIBLTE_X2AP_MME_GROUP_ID_STRUCT                                    *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - MME-Group-ID
    if(LIBLTE_X2AP_MME_GROUP_ID_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MME_GROUP_ID_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mme_group_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MME_GROUP_ID_STRUCT                                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - MME-Group-ID
    if(LIBLTE_X2AP_MME_GROUP_ID_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MME_GROUP_ID_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MME_Code STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mme_code(
  LIBLTE_X2AP_MME_CODE_STRUCT                                        *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - MME-Code
    if(LIBLTE_X2AP_MME_CODE_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MME_CODE_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mme_code(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MME_CODE_STRUCT                                        *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - MME-Code
    if(LIBLTE_X2AP_MME_CODE_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MME_CODE_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MBMS_Service_Area_Identity STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mbms_service_area_identity(
  LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_STRUCT                                  *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - MBMS_Service_Area_Identity
    if(LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mbms_service_area_identity(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_STRUCT                                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - MBMS_Service_Area_Identity
    if(LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE PLMN_identity STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_plmn_identity(
  LIBLTE_X2AP_PLMN_IDENTITY_STRUCT                              *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - PLMN_identity
    if(LIBLTE_X2AP_PLMN_IDENTITY_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_PLMN_IDENTITY_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_plmn_identity(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_PLMN_IDENTITY_STRUCT                              *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - PLMN_identity
    if(LIBLTE_X2AP_PLMN_IDENTITY_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_PLMN_IDENTITY_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE RRC_Context DYNAMIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_rrc_context(
  LIBLTE_X2AP_RRC_CONTEXT_STRUCT                                   *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - RRC-Container
    // Length
    if(ie->n_octets < 128) {
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 7);
    } else if(ie->n_octets < 16383) {
      liblte_value_2_bits(1,            ptr, 1);
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
      return err; // at least report error, by ZY
    }
    
    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_rrc_context(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_RRC_CONTEXT_STRUCT                                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - RRC-Context
    // Length
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->n_octets = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->n_octets = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
        return err; // at least report error, by ZY
      }
    }

    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE TAC STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_tac(
  LIBLTE_X2AP_TAC_STRUCT                                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - TAC
    if(LIBLTE_X2AP_TAC_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_TAC_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_tac(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_TAC_STRUCT                                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - TAC
    if(LIBLTE_X2AP_TAC_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_TAC_OCTET_STRING_LEN;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE TargetCellInUTRAN DYNAMIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_targetcellinutran(
  LIBLTE_X2AP_TARGETCELLINUTRAN_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - TargetCellInUTRAN
    // Length
    if(ie->n_octets < 128) {
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 7);
    } else if(ie->n_octets < 16383) {
      liblte_value_2_bits(1,            ptr, 1);
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
      return err; // at least report error, by ZY
    }
    
    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_targetcellinutran(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TARGETCELLINUTRAN_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - TargetCellInUTRAN
    // Length
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->n_octets = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->n_octets = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
        return err; // at least report error, by ZY
      }
    }

    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE TargeteNBtoSource_eNBTransparentContainer DYNAMIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_targetenbtosource_enbtransparentcontainer(
  LIBLTE_X2AP_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - TargeteNBtoSource_eNBTransparentContainer
    // Length
    if(ie->n_octets < 128) {
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 7);
    } else if(ie->n_octets < 16383) {
      liblte_value_2_bits(1,            ptr, 1);
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
      return err; // at least report error, by ZY
    }
    
    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_targetenbtosource_enbtransparentcontainer(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - TargeteNBtoSource_eNBTransparentContainer
    // Length
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->n_octets = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->n_octets = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
        return err; // at least report error, by ZY
      }
    }

    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UL_RLF_Report_Container DYNAMIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ue_rlf_report_container(
  LIBLTE_X2AP_UE_RLF_REPORT_CONTAINER_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - UL_RLF_Report_Container
    // Length
    if(ie->n_octets < 128) {
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 7);
    } else if(ie->n_octets < 16383) {
      liblte_value_2_bits(1,            ptr, 1);
      liblte_value_2_bits(0,            ptr, 1);
      liblte_value_2_bits(ie->n_octets, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
      return err; // at least report error, by ZY
    }
    
    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ue_rlf_report_container(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UE_RLF_REPORT_CONTAINER_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Dynamic octet string - UL_RLF_Report_Container
    // Length
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->n_octets = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->n_octets = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
        return err; // at least report error, by ZY
      }
    }

    // Octets
    uint32_t i;
    for(i=0;i<ie->n_octets;i++) {
      ie->buffer[i] = liblte_bits_2_value(ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/* ENUMERATED */

/*******************************************************************************
/* ProtocolIE AdditionalSpecialSubframePatterns ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_additionalspecialsubframepatterns(
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM_EXT                               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("AdditionalSpecialSubframePatterns error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 4);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_additionalspecialsubframepatterns(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM_EXT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("AdditionalSpecialSubframePatterns error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM)liblte_bits_2_value(ptr, 4);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CauseMisc ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_causemisc(
  LIBLTE_X2AP_CAUSEMISC_ENUM_EXT                                     *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseMisc error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_causemisc(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CAUSEMISC_ENUM_EXT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseMisc error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CAUSEMISC_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CauseProtocol ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_causeprotocol(
  LIBLTE_X2AP_CAUSEPROTOCOL_ENUM_EXT                                 *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseProtocol error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_causeprotocol(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CAUSEPROTOCOL_ENUM_EXT                                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseProtocol error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CAUSEPROTOCOL_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CauseRadioNetwork ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_causeradionetwork(
  LIBLTE_X2AP_CAUSERADIONETWORK_ENUM_EXT                             *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseRadioNetwork error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 6);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_causeradionetwork(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CAUSERADIONETWORK_ENUM_EXT                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseRadioNetwork error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CAUSERADIONETWORK_ENUM)liblte_bits_2_value(ptr, 6);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CauseTransport ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_causetransport(
  LIBLTE_X2AP_CAUSETRANSPORT_ENUM_EXT                                *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseTransport error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_causetransport(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CAUSETRANSPORT_ENUM_EXT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CauseTransport error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CAUSETRANSPORT_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Cell_Size ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cell_size(
  LIBLTE_X2AP_CELL_SIZE_ENUM_EXT                                     *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Cell_Size error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cell_size(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CELL_SIZE_ENUM_EXT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Cell_Size error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CELL_SIZE_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CSGMembershipStatus ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_csgmembershipstatus(
  LIBLTE_X2AP_CSGMEMBERSHIPSTATUS_ENUM                               *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 1);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_csgmembershipstatus(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_CSGMEMBERSHIPSTATUS_ENUM                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_CSGMEMBERSHIPSTATUS_ENUM)liblte_bits_2_value(ptr, 1);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CyclicPrefixDL ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cyclicprefixdl(
  LIBLTE_X2AP_CYCLICPREFIXDL_ENUM_EXT                                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CyclicPrefixDL error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cyclicprefixdl(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CYCLICPREFIXDL_ENUM_EXT                                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CyclicPrefixDL error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CYCLICPREFIXDL_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CyclicPrefixUL ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cyclicprefixul(
  LIBLTE_X2AP_CYCLICPREFIXUL_ENUM_EXT                                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CyclicPrefixUL error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cyclicprefixul(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CYCLICPREFIXUL_ENUM_EXT                                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CyclicPrefixUL error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_CYCLICPREFIXUL_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE DL_Forwarding ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_dl_forwarding(
  LIBLTE_X2AP_DL_FORWARDING_ENUM_EXT                                 *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("DL_Forwarding error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    // liblte_value_2_bits(ie->e, ptr, 0); changed by ZY
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_dl_forwarding(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_DL_FORWARDING_ENUM_EXT                                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("DL_Forwarding error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    // ie->e = (LIBLTE_X2AP_DL_FORWARDING_ENUM)liblte_bits_2_value(ptr, 0); changed by ZY
    ie->e = (LIBLTE_X2AP_DL_FORWARDING_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE DeactivationIndication ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_deactivationindication(
  LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM_EXT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("DeactivationIndication error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    // liblte_value_2_bits(ie->e, ptr, 0); changed by ZY
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_deactivationindication(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM_EXT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("DeactivationIndication error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    // ie->e = (LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM)liblte_bits_2_value(ptr, 0); changed by ZY
    ie->e = (LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE EventType ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_eventtype(
  LIBLTE_X2AP_EVENTTYPE_ENUM_EXT                                     *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("EventType error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_eventtype(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_EVENTTYPE_ENUM_EXT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("EventType error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_EVENTTYPE_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ForbiddenInterRATs ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_forbiddeninterrats(
  LIBLTE_X2AP_FORBIDDENINTERRATS_ENUM_EXT                            *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ForbiddenInterRATs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_forbiddeninterrats(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_FORBIDDENINTERRATS_ENUM_EXT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ForbiddenInterRATs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_FORBIDDENINTERRATS_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE HandoverReportType ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_handoverreporttype(
  LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM_EXT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("HandoverReportType error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_handoverreporttype(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM_EXT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("HandoverReportType error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE InvokeIndication ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_invokeindication(
  LIBLTE_X2AP_INVOKEINDICATION_ENUM_EXT                          *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("InvokeIndication error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_invokeindication(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_INVOKEINDICATION_ENUM_EXT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("InvokeIndication error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_INVOKEINDICATION_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
  
/*******************************************************************************
/* ProtocolIE Links_to_log ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_links_to_log(
  LIBLTE_X2AP_LINKS_TO_LOG_ENUM_EXT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Links_to_log error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_links_to_log(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_LINKS_TO_LOG_ENUM_EXT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Links_to_log error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_LINKS_TO_LOG_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE LoadIndicator ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_loadindicator(
  LIBLTE_X2AP_LOADINDICATOR_ENUM_EXT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("LoadIndicator error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_loadindicator(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_LOADINDICATOR_ENUM_EXT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("LoadIndicator error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_LOADINDICATOR_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE M1ReportingTrigger ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_m1reportingtrigger(
  LIBLTE_X2AP_M1REPORTINGTRIGGER_ENUM_EXT                      *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M1ReportingTrigger error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_m1reportingtrigger(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_M1REPORTINGTRIGGER_ENUM_EXT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M1ReportingTrigger error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_M1REPORTINGTRIGGER_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE M3period ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_m3period(
  LIBLTE_X2AP_M3PERIOD_ENUM_EXT                                *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M3period error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_m3period(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_M3PERIOD_ENUM_EXT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M3period error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_M3PERIOD_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE M4period ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_m4period(
  LIBLTE_X2AP_M4PERIOD_ENUM_EXT                                *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M4period error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_m4period(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_M4PERIOD_ENUM_EXT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M4period error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_M4PERIOD_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE M5period ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_m5period(
  LIBLTE_X2AP_M5PERIOD_ENUM_EXT                                *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M5period error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_m5period(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_M5PERIOD_ENUM_EXT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("M5period error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_M5PERIOD_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MDT_Activation ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mdt_activation(
  LIBLTE_X2AP_MDT_ACTIVATION_ENUM_EXT                          *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("MDT_Activation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mdt_activation(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MDT_ACTIVATION_ENUM_EXT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("MDT_Activation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_MDT_ACTIVATION_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ManagementBasedMDTAllowed ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_managementbasedmdtallowed(
  LIBLTE_X2AP_MANAGEMENTBASEDMDTALLOWED_ENUM_EXT               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ManagementBasedMDTAllowed error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_managementbasedmdtallowed(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MANAGEMENTBASEDMDTALLOWED_ENUM_EXT               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ManagementBasedMDTAllowed error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_MANAGEMENTBASEDMDTALLOWED_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Number_of_Antennaports ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_number_of_antennaports(
  LIBLTE_X2AP_NUMBER_OF_ANTENNAPORTS_ENUM_EXT                        *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Number_of_Antennaports error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_number_of_antennaports(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_NUMBER_OF_ANTENNAPORTS_ENUM_EXT                        *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Number_of_Antennaports error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_NUMBER_OF_ANTENNAPORTS_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Pre_emptionCapability ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_pre_emptioncapability(
  LIBLTE_X2AP_PRE_EMPTIONCAPABILITY_ENUM                       *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 1);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_pre_emptioncapability(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_PRE_EMPTIONCAPABILITY_ENUM                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_PRE_EMPTIONCAPABILITY_ENUM)liblte_bits_2_value(ptr, 1);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Pre_emptionVulnerability ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_pre_emptionvulnerability(
  LIBLTE_X2AP_PRE_EMPTIONVULNERABILITY_ENUM                          *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 1);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_pre_emptionvulnerability(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PRE_EMPTIONVULNERABILITY_ENUM                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_PRE_EMPTIONVULNERABILITY_ENUM)liblte_bits_2_value(ptr, 1);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE RadioframeAllocationPeriod ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_radioframeallocationperiod(
  LIBLTE_X2AP_RADIOFRAMEALLOCATIONPERIOD_ENUM_EXT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RadioframeAllocationPeriod error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_radioframeallocationperiod(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_RADIOFRAMEALLOCATIONPERIOD_ENUM_EXT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RadioframeAllocationPeriod error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_RADIOFRAMEALLOCATIONPERIOD_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Registration_Request ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_registration_request(
  LIBLTE_X2AP_REGISTRATION_REQUEST_ENUM_EXT                              *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Registration_Request error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_registration_request(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REGISTRATION_REQUEST_ENUM_EXT                              *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Registration_Request error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_REGISTRATION_REQUEST_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ReportAmountMDT ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_reportamountmdt(
  LIBLTE_X2AP_REPORTAMOUNTMDT_ENUM                             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 3);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_reportamountmdt(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REPORTAMOUNTMDT_ENUM                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_REPORTAMOUNTMDT_ENUM)liblte_bits_2_value(ptr, 3);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ReportArea ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_reportarea(
  LIBLTE_X2AP_REPORTAREA_ENUM_EXT                              *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ReportArea error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_reportarea(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REPORTAREA_ENUM_EXT                              *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ReportArea error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_REPORTAREA_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ReportIntervalMDT ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_reportintervalmdt(
  LIBLTE_X2AP_REPORTINTERVALMDT_ENUM                           *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    liblte_value_2_bits(*ie, ptr, 4);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_reportintervalmdt(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REPORTINTERVALMDT_ENUM                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Enum - *ie
    *ie = (LIBLTE_X2AP_REPORTINTERVALMDT_ENUM)liblte_bits_2_value(ptr, 4);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE RNTP_Threshold ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_rntp_threshold(
  LIBLTE_X2AP_RNTP_THRESHOLD_ENUM_EXT                           *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RNTP_Threshold error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 4);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_rntp_threshold(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_RNTP_THRESHOLD_ENUM_EXT                           *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RNTP_Threshold error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_RNTP_THRESHOLD_ENUM)liblte_bits_2_value(ptr, 4);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE RRCConnReestabIndicator ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_rrcconnreestabindicator(
  LIBLTE_X2AP_RRCCONNREESTABINDICATOR_ENUM_EXT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RRCConnReestabIndicator error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
//Luca: fix conn
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_rrcconnreestabindicator(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_RRCCONNREESTABINDICATOR_ENUM_EXT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RRCConnReestabIndicator error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_RRCCONNREESTABINDICATOR_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE RRCConnSetupIndicator ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_rrcconnsetupindicator(
  LIBLTE_X2AP_RRCCONNSETUPINDICATOR_ENUM_EXT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RRCConnSetupIndicator error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
//Luca: fix conn
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_rrcconnsetupindicator(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_RRCCONNSETUPINDICATOR_ENUM_EXT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("RRCConnSetupIndicator error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_RRCCONNSETUPINDICATOR_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE SRVCCOperationPossible ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_srvccoperationpossible(
  LIBLTE_X2AP_SRVCCOPERATIONPOSSIBLE_ENUM_EXT                  *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("SRVCCOperationPossible error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_srvccoperationpossible(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SRVCCOPERATIONPOSSIBLE_ENUM_EXT                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("SRVCCOperationPossible error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_SRVCCOPERATIONPOSSIBLE_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE SubframeAssignment ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_subframeassignment(
  LIBLTE_X2AP_SUBFRAMEASSIGNMENT_ENUM_EXT                   *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("SubframeAssignment error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_subframeassignment(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SUBFRAMEASSIGNMENT_ENUM_EXT                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("SubframeAssignment error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_SUBFRAMEASSIGNMENT_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE SpecialSubframePatterns ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_specialsubframepatterns(
  LIBLTE_X2AP_SPECIALSUBFRAMEPATTERNS_ENUM_EXT                   *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("SpecialSubframePatterns error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 4);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_specialsubframepatterns(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SPECIALSUBFRAMEPATTERNS_ENUM_EXT                  *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("SpecialSubframePatterns error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_SPECIALSUBFRAMEPATTERNS_ENUM)liblte_bits_2_value(ptr, 4);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE TimeToWait ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_timetowait(
  LIBLTE_X2AP_TIMETOWAIT_ENUM_EXT                              *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TimeToWait error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_timetowait(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TIMETOWAIT_ENUM_EXT                              *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TimeToWait error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_TIMETOWAIT_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE TraceDepth ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_tracedepth(
  LIBLTE_X2AP_TRACEDEPTH_ENUM_EXT                              *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TraceDepth error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_tracedepth(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TRACEDEPTH_ENUM_EXT                              *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TraceDepth error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_TRACEDEPTH_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Transmission_Bandwidth ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_transmission_bandwidth(
  LIBLTE_X2AP_TRANSMISSION_BANDWIDTH_ENUM_EXT                              *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Transmission_Bandwidth error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_transmission_bandwidth(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TRANSMISSION_BANDWIDTH_ENUM_EXT                              *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Transmission_Bandwidth error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_TRANSMISSION_BANDWIDTH_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* ProtocolIE TypeOfError ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_typeoferror(
  LIBLTE_X2AP_TYPEOFERROR_ENUM_EXT                             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TypeOfError error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_typeoferror(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TYPEOFERROR_ENUM_EXT                             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("TypeOfError error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_TYPEOFERROR_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UL_InterferenceOverloadIndication_Item ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_interferenceoverloadindication_item(
  LIBLTE_X2AP_UL_INTERFERENCEOVERLOADINDICATION_ITEM_ENUM_EXT                     *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("UL_InterferenceOverloadIndication_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 2);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_interferenceoverloadindication_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_INTERFERENCEOVERLOADINDICATION_ITEM_ENUM_EXT                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("UL_InterferenceOverloadIndication_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_UL_INTERFERENCEOVERLOADINDICATION_ITEM_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ABSInformationFDD SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_absinformationfdd(
  LIBLTE_X2AP_ABSINFORMATIONFDD_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationFDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    for (uint32_t i = 0; i < 40; ++i)
      liblte_value_2_bits(ie->abs_pattern_info[i], ptr, 1);
    
    liblte_value_2_bits(ie->numberofCellSpecificAntennaPorts, ptr, 2);

    for (uint32_t i = 0; i < 40; ++i)
      liblte_value_2_bits(ie->measurement_subset[i], ptr, 1);

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_absinformationfdd(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ABSINFORMATIONFDD_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationFDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    for (uint32_t i = 0; i < 40; ++i)
      ie->abs_pattern_info[i] = liblte_bits_2_value(ptr, 1);

    ie->numberofCellSpecificAntennaPorts = (decltype(ie->numberofCellSpecificAntennaPorts))liblte_bits_2_value(ptr, 2);

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ABSInformationFDD_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_absinformationfdd_ext(
  LIBLTE_X2AP_MESSAGE_ABSINFORMATIONFDD_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationFDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_absinformationfdd_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ABSINFORMATIONFDD_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationFDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ABSInformationTDD SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_absinformationtdd(
  LIBLTE_X2AP_ABSINFORMATIONTDD_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationTDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    for (uint32_t i = 0; i < 70; ++i)
      liblte_value_2_bits(ie->abs_pattern_info[i], ptr, 1);
    
    liblte_value_2_bits(ie->numberofCellSpecificAntennaPorts, ptr, 2);

    for (uint32_t i = 0; i < 70; ++i)
      liblte_value_2_bits(ie->measurement_subset[i], ptr, 1);

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_absinformationtdd(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ABSINFORMATIONTDD_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationTDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    for (uint32_t i = 0; i < 70; ++i)
      ie->abs_pattern_info[i] = liblte_bits_2_value(ptr, 1);

    ie->numberofCellSpecificAntennaPorts = (decltype(ie->numberofCellSpecificAntennaPorts))liblte_bits_2_value(ptr, 2);

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ABSInformationTDD_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_absinformationtdd_ext(
  LIBLTE_X2AP_MESSAGE_ABSINFORMATIONTDD_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationTDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_absinformationtdd_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ABSINFORMATIONTDD_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ABSInformationTDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ABSInformation CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_absinformation(
  LIBLTE_X2AP_ABSINFORMATION_STRUCT                            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if (ie != NULL &&
      ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ABSInformation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Choice type
    liblte_value_2_bits(ie->choice_type, ptr, 2);
    // Choice
    if (ie->choice_type == LIBLTE_X2AP_ABSINFORMATION_CHOICE_FDD) {
      if (liblte_x2ap_pack_absinformationfdd(&ie->choice.fdd, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_ABSINFORMATION_CHOICE_TDD) {
      if (liblte_x2ap_pack_absinformationtdd(&ie->choice.tdd, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_ABSINFORMATION_CHOICE_ABS_INACTIVE) {
      // NULL: do nothing
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_absinformation(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ABSINFORMATION_STRUCT                            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if (ie != NULL &&
      ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("ABSInformation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Choice type
    ie->choice_type = (LIBLTE_X2AP_ABSINFORMATION_CHOICE_ENUM)liblte_bits_2_value(ptr, 2);
    // Choice
    if (ie->choice_type == LIBLTE_X2AP_ABSINFORMATION_CHOICE_FDD) {
      if (liblte_x2ap_unpack_absinformationfdd(ptr, &ie->choice.fdd) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_ABSINFORMATION_CHOICE_TDD) {
      if (liblte_x2ap_unpack_absinformationtdd(ptr, &ie->choice.tdd) != LIBLTE_SUCCESS){
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_GLOBAL) {
      // NULL: do nothing
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UsableABSInformationFDD SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_usableabsinformationfdd(
  LIBLTE_X2AP_USABLEABSINFORMATIONFDD_STRUCT                               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationFDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    for (uint32_t i = 0; i < 40; ++i)
      liblte_value_2_bits(ie->usable_abs_pattern_info[i], ptr, 1);

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_usableabsinformationfdd(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_USABLEABSINFORMATIONFDD_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationFDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    for (uint32_t i = 0; i < 40; ++i)
      ie->usable_abs_pattern_info[i] = liblte_bits_2_value(ptr, 1);

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message UsableABSInformationFDD_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_usableabsinformationfdd_ext(
  LIBLTE_X2AP_MESSAGE_USABLEABSINFORMATIONFDD_EXT_STRUCT                   *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationFDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_usableabsinformationfdd_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_USABLEABSINFORMATIONFDD_EXT_STRUCT                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationFDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UsableABSInformationTDD SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_usableabsinformationtdd(
  LIBLTE_X2AP_USABLEABSINFORMATIONTDD_STRUCT                               *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationTDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    for (uint32_t i = 0; i < 70; ++i)
      liblte_value_2_bits(ie->usable_abs_pattern_info[i], ptr, 1);

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_usableabsinformationtdd(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_USABLEABSINFORMATIONTDD_STRUCT                               *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationTDD error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    for (uint32_t i = 0; i < 70; ++i)
      ie->usable_abs_pattern_info[i] = liblte_bits_2_value(ptr, 1);

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message UsableABSInformationTDD_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_usableabsinformationtdd_ext(
  LIBLTE_X2AP_MESSAGE_USABLEABSINFORMATIONTDD_EXT_STRUCT                   *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationTDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_usableabsinformationtdd_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_USABLEABSINFORMATIONTDD_EXT_STRUCT                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("UsableABSInformationTDD_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE UsableABSInformation CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_usableabsinformation(
  LIBLTE_X2AP_USABLEABSINFORMATION_STRUCT                          *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if (ie != NULL &&
      ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("UsableABSInformation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Choice type
    liblte_value_2_bits(ie->choice_type, ptr, 1);
    // Choice
    if (ie->choice_type == LIBLTE_X2AP_USABLEABSINFORMATION_CHOICE_FDD) {
      if (liblte_x2ap_pack_usableabsinformationfdd(&ie->choice.fdd, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_USABLEABSINFORMATION_CHOICE_TDD) {
      if (liblte_x2ap_pack_usableabsinformationtdd(&ie->choice.tdd, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    else
      return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_usableabsinformation(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_USABLEABSINFORMATION_STRUCT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if (ie != NULL &&
      ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("UsableABSInformation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Choice type
    ie->choice_type = (LIBLTE_X2AP_USABLEABSINFORMATION_CHOICE_ENUM)liblte_bits_2_value(ptr, 1);
    // Choice
    if (ie->choice_type == LIBLTE_X2AP_USABLEABSINFORMATION_CHOICE_FDD) {
      if (liblte_x2ap_unpack_usableabsinformationfdd(ptr, &ie->choice.fdd) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    else if (ie->choice_type == LIBLTE_X2AP_USABLEABSINFORMATION_CHOICE_TDD) {
      if (liblte_x2ap_unpack_usableabsinformationtdd(ptr, &ie->choice.tdd) != LIBLTE_SUCCESS){
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    else
      return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ABS_Status SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_abs_status(
  LIBLTE_X2AP_ABS_STATUS_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ABS_Status error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present, ptr, 1);
    
    if (liblte_x2ap_pack_usableabsinformation(&ie->usableABSInformation, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_abs_status(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ABS_STATUS_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ABS_Status error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if (liblte_x2ap_unpack_usableabsinformation(ptr, &ie->usableABSInformation) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ABS_Status_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_abs_status_ext(
  LIBLTE_X2AP_MESSAGE_ABS_STATUS_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ABS_Status_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_abs_status_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ABS_STATUS_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ABS_Status_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE AdditionalSpecialSubframe_Info SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_additionalspecialsubframe_info(
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAME_INFO_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("AdditionalSpecialSubframe_Info error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    if (liblte_x2ap_pack_additionalspecialsubframepatterns(&ie->additionalspecialSubframePatterns, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    
    if (liblte_x2ap_pack_cyclicprefixdl(&ie->cyclicPrefixDL, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    if (liblte_x2ap_pack_cyclicprefixul(&ie->cyclicPrefixUL, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_additionalspecialsubframe_info(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAME_INFO_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("AdditionalSpecialSubframe_Info error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if (liblte_x2ap_unpack_additionalspecialsubframepatterns(ptr, &ie->additionalspecialSubframePatterns) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    
    if (liblte_x2ap_unpack_cyclicprefixdl(ptr, &ie->cyclicPrefixDL) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (liblte_x2ap_unpack_cyclicprefixul(ptr, &ie->cyclicPrefixUL) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message AdditionalSpecialSubframe_Info_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_additionalspecialsubframe_info_ext(
  LIBLTE_X2AP_MESSAGE_ADDITIONALSPECIALSUBFRAME_INFO_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("AdditionalSpecialSubframe_Info_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_additionalspecialsubframe_info_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ADDITIONALSPECIALSUBFRAME_INFO_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("AdditionalSpecialSubframe_Info_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE AS_SecurityInformation SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_as_securityinformation(
  LIBLTE_X2AP_AS_SECURITYINFORMATION_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("AS_SecurityInformation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    if (liblte_x2ap_pack_key_enodeb_star(&ie->key_eNodeB_star, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    
    if (liblte_x2ap_pack_nexthopchainingcount(&ie->nextHopChainingCount, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_as_securityinformation(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_AS_SECURITYINFORMATION_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("AS_SecurityInformation error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if (liblte_x2ap_unpack_key_enodeb_star(ptr, &ie->key_eNodeB_star) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    
    if (liblte_x2ap_unpack_nexthopchainingcount(ptr, &ie->nextHopChainingCount) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message AS_SecurityInformation_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_as_securityinformation_ext(
  LIBLTE_X2AP_MESSAGE_AS_SECURITYINFORMATION_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("AS_SecurityInformation_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_as_securityinformation_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_AS_SECURITYINFORMATION_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("AS_SecurityInformation_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE AllocationAndRetentionPriority SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_allocationandretentionpriority(
  LIBLTE_X2AP_ALLOCATIONANDRETENTIONPRIORITY_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("AllocationAndRetentionPriority error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    if (liblte_x2ap_pack_prioritylevel(&ie->priorityLevel, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    
    if (liblte_x2ap_pack_pre_emptioncapability(&ie->pre_emptioncapability, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    if (liblte_x2ap_pack_pre_emptionvulnerability(&ie->pre_emptionVulnerability, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_allocationandretentionpriority(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ALLOCATIONANDRETENTIONPRIORITY_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("AllocationAndRetentionPriority error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if (liblte_x2ap_unpack_prioritylevel(ptr, &ie->priorityLevel) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    
    if (liblte_x2ap_unpack_pre_emptioncapability(ptr, &ie->pre_emptioncapability) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (liblte_x2ap_unpack_pre_emptionvulnerability(ptr, &ie->pre_emptionVulnerability) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message AllocationAndRetentionPriority_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_allocationandretentionpriority_ext(
  LIBLTE_X2AP_MESSAGE_ALLOCATIONANDRETENTIONPRIORITY_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("AllocationAndRetentionPriority_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_allocationandretentionpriority_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ALLOCATIONANDRETENTIONPRIORITY_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("AllocationAndRetentionPriority_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE BroadcastPLMNs_Item DYNAMIC SEQUENCE OF
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_broadcastplmns_item(
  LIBLTE_X2AP_BROADCASTPLMNS_ITEM_STRUCT                                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    liblte_value_2_bits(ie->len, ptr, 3);
    
    for (uint32_t i = 0; i < ie->len; ++i)
      if (liblte_x2ap_pack_plmn_identity(&ie->buffer[i], ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;

    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_broadcastplmns_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_BROADCASTPLMNS_ITEM_STRUCT                                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->len = liblte_bits_2_value(ptr, 3);
    
    for (uint32_t i = 0; i < ie->len; ++i)
      if (liblte_x2ap_unpack_plmn_identity(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;

    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE Cause CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cause(
  LIBLTE_X2AP_CAUSE_STRUCT                                     *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Cause error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Choice type
    liblte_value_2_bits(ie->choice_type, ptr, 3);

    // Choice
    if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_RADIONETWORK) {
      if(liblte_x2ap_pack_causeradionetwork(&ie->choice.radioNetwork, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_TRANSPORT) {
      if(liblte_x2ap_pack_causetransport(&ie->choice.transport, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_PROTOCOL) {
      if(liblte_x2ap_pack_causeprotocol(&ie->choice.protocol, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_MISC) {
      if(liblte_x2ap_pack_causemisc(&ie->choice.misc, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    } 
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cause(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CAUSE_STRUCT                                     *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("Cause error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Choice type
    ie->choice_type = (LIBLTE_X2AP_CAUSE_CHOICE_ENUM)liblte_bits_2_value(ptr, 3);

    // Choice
    if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_RADIONETWORK) {
      if(liblte_x2ap_unpack_causeradionetwork(ptr, &ie->choice.radioNetwork) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_TRANSPORT) {
      if(liblte_x2ap_unpack_causetransport(ptr, &ie->choice.transport) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_PROTOCOL) {
      if(liblte_x2ap_unpack_causeprotocol(ptr, &ie->choice.protocol) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_CAUSE_CHOICE_MISC) {
      if(liblte_x2ap_unpack_causemisc(ptr, &ie->choice.misc) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    } 
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ECGI SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ecgi(
  LIBLTE_X2AP_ECGI_STRUCT                                *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ECGI error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present ? 1:0, ptr, 1);

    if (liblte_x2ap_pack_plmn_identity(&ie->pLMN_Identity, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    
    if (liblte_x2ap_pack_eutrancellidentifier(&ie->eUTRANcellIdentifier, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;

    liblte_align_up_zero(ptr, 8);
    
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ecgi(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ECGI_STRUCT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ECGI error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if (liblte_x2ap_unpack_plmn_identity(ptr, &ie->pLMN_Identity) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    
    if (liblte_x2ap_unpack_eutrancellidentifier(ptr, &ie->eUTRANcellIdentifier) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if (ie->iE_Extensions_present)
      if (liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    liblte_align_up(ptr, 8);
    
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ECGI_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_ecgi_ext(
  LIBLTE_X2AP_MESSAGE_ECGI_EXT_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("ECGI_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ecgi_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ECGI_EXT_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("ECGI_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CellIdListforMDT DYNAMIC SEQUENCE OF
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellidlistformdt(
  LIBLTE_X2AP_CELLIDLISTFORMDT_STRUCT                          *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_x2ap_log_print("CellIdListforMDT pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 5);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_ecgi(&ie->buffer[i], ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellidlistformdt(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLIDLISTFORMDT_STRUCT                          *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Length
    ie->len = liblte_bits_2_value(ptr, 5) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_x2ap_log_print("CellIdListforMDT unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_ecgi(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CellBasedMDT SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellbasedmdt(
  LIBLTE_X2AP_CELLBASEDMDT_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CellBasedMDT error: S1AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);

    if(liblte_x2ap_pack_cellidlistformdt(&ie->cellIdListforMDT, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    if(ie->iE_Extensions_present) {
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellbasedmdt(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLBASEDMDT_STRUCT            *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_x2ap_log_print("CellBasedMDT error: S1AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if(liblte_x2ap_unpack_cellidlistformdt(ptr, &ie->cellIdListforMDT) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    if(ie->iE_Extensions_present) {
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellBasedMDT_Ext STRUCT
********************************************************************************/
typedef struct{
  bool                                                         ext;
}LIBLTE_X2AP_MESSAGE_CELLBASEDMDT_EXT_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellbasedmdt_ext(
  LIBLTE_X2AP_MESSAGE_CELLBASEDMDT_EXT_STRUCT *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up_zero(ptr, 8);
    if (ie->ext) {
      liblte_x2ap_log_print("CellBasedMDT_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(ptr, 8);
     err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellbasedmdt_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLBASEDMDT_EXT_STRUCT *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    liblte_align_up(ptr, 8);
    ie->ext = liblte_bits_2_value(ptr, 1);
    if (ie->ext) {
      liblte_x2ap_log_print("CellBasedMDT_Ext error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ErrorIndication STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_errorindication(
  LIBLTE_X2AP_MESSAGE_ERRORINDICATION_STRUCT                         *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 4;
    if(!msg->Old_eNB_UE_X2AP_ID_present)
      n_ie--;
    if(!msg->New_eNB_UE_X2AP_ID_present)
      n_ie--;
    if(!msg->Cause_present)
      n_ie--;
    if(!msg->CriticalityDiagnostics_present)
      n_ie--;
    //liblte_value_2_bits(n_ie, ptr, 16);
    liblte_value_2_bits(n_ie, ptr, 3);  //Modified by Luca, ub 4.

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - MME_UE_X2AP_ID
    if(msg->Old_eNB_UE_X2AP_ID_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_ue_x2ap_id(&msg->Old_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_OLD_ENB_UE_X2AP_ID,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - eNB_UE_X2AP_ID
    if(msg->New_eNB_UE_X2AP_ID_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_ue_x2ap_id(&msg->New_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_NEW_ENB_UE_X2AP_ID,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - Cause
    if(msg->Cause_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cause(&msg->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CAUSE,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - CriticalityDiagnostics
    if(msg->CriticalityDiagnostics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_criticalitydiagnostics(&msg->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_errorindication(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_ERRORINDICATION_STRUCT                         *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->Old_eNB_UE_X2AP_ID_present = false;
    msg->New_eNB_UE_X2AP_ID_present = false;
    msg->Cause_present = false;
    msg->CriticalityDiagnostics_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    //n_ie = liblte_bits_2_value(ptr, 16);
    n_ie = liblte_bits_2_value(ptr, 3); //Modified by Luca, ub = 4

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_OLD_ENB_UE_X2AP_ID == ie_id) {
        if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->Old_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->Old_eNB_UE_X2AP_ID_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_NEW_ENB_UE_X2AP_ID == ie_id) {
        if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->New_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->New_eNB_UE_X2AP_ID_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &msg->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->Cause_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &msg->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->CriticalityDiagnostics_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*-- **************************************************************
 *--
 *-- RESET REQUEST
 *--
 *-- **************************************************************
 */

/*******************************************************************************
/* Protocol Message ResetRequest STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_resetrequest(
  LIBLTE_X2AP_MESSAGE_RESETREQUEST_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
   {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cause(&ie->cause, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CAUSE,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
      err = LIBLTE_SUCCESS;
   }
   return err;   
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_resetrequest(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RESETREQUEST_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

   
    if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie_id == LIBLTE_X2AP_IE_ID_CAUSE)
    	if(liblte_x2ap_unpack_cause(ptr, &ie->Cause) != LIBLTE_SUCCESS)
    		return LIBLTE_ERROR_DECODE_FAIL;
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
    }
    return err;
}

/*******************************************************************************
/* Protocol Message ResetResponse STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_resetresponse(
  LIBLTE_X2AP_MESSAGE_RESETRESPONSE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
   {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    liblte_value_2_bits(ie->CriticalityDiagnostics_present?1:0 , ptr, 1);
    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    if(ie->CriticalityDiagnostics_present)
    {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    
      err = LIBLTE_SUCCESS;
   }
   return err;   
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_resetresponse(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RESETRESPONSE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    ie->CriticalityDiagnostics_present = liblte_bits_2_value(ptr, 1);

    
    if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie_id == LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS)
    	if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS)
    		return LIBLTE_ERROR_DECODE_FAIL;
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
    }
    
    return err;
}

/*******************************************************************************
/* ProtocolIE CellInformation_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellinformation_item(
  LIBLTE_X2AP_CELLINFORMATION_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
  	liblte_value_2_bits(ie->ext?1:0, ptr, 1);
  	if(ie->ext){
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    liblte_value_2_bits(ie->ul_InterferenceOverloadIndication_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->ul_HighInterferenceIndicationInfo_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->relativeNarrowbandTxPower_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->cell_ID, ptr) != LIBLTE_SUCCESS)
    	return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->ul_InterferenceOverloadIndication_present)
    	if(liblte_x2ap_pack_ul_interferenceoverloadindication(&ie->ul_InterferenceOverloadIndication, ptr) != LIBLTE_SUCCESS)
    		//Luca: this func is TODO
    		return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->ul_HighInterferenceIndicationInfo_present)
    	if(liblte_x2ap_pack_ul_highinterferenceindicationinfo(&ie->ul_HighInterferenceIndicationInfo, ptr) != LIBLTE_SUCCESS)
    		//Luca: func TODO
    		return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->relativeNarrowbandTxPower_present)
    	if(liblte_x2ap_pack_relativenarrowbandtxpower(&ie->relativeNarrowbandTxPower, ptr) != LIBLTE_SUCCESS)
    		return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
    	if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
    		return LIBLTE_ERROR_ENCODE_FAIL;

    err = LIBLTE_SUCCESS;

  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellinformation_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLINFORMATION_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
  	ie->ext = liblte_bits_2_value(ptr, 1);
  	if(ie->ext){
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->ul_InterferenceOverloadIndication_present = liblte_bits_2_value(ptr, 1);
    ie->ul_HighInterferenceIndicationInfo_present = liblte_bits_2_value(ptr, 1);
    ie->relativeNarrowbandTxPower_present = liblte_bits_2_value(ptr, 1);
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if(liblte_x2ap_unpack_ecgi(ptr, &ie->cell_ID) != LIBLTE_SUCCESS)
    	return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->ul_InterferenceOverloadIndication_present)
    	if(liblte_x2ap_unpack_ul_interferenceoverloadindication(ptr, &ie->ul_InterferenceOverloadIndication) != LIBLTE_SUCCESS)
    		//Luca: this func is TODO
    		return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->ul_HighInterferenceIndicationInfo_present)
    	if(liblte_x2ap_unpack_ul_highinterferenceindicationinfo(ptr, &ie->ul_HighInterferenceIndicationInfo) != LIBLTE_SUCCESS)
    		//Luca: func TODO
    		return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->relativeNarrowbandTxPower_present)
    	if(liblte_x2ap_unpack_relativenarrowbandtxpower(ptr, &ie->relativeNarrowbandTxPower) != LIBLTE_SUCCESS)
    		return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
    	if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
    		return LIBLTE_ERROR_DECODE_FAIL;

    err = LIBLTE_SUCCESS;

  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellInformation_Item_Ext STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellinformation_item_ext(
  LIBLTE_X2AP_MESSAGE_CELLINFORMATION_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 2;
    if(!ie->ABSInformation_present)
      n_ie--;
    if(!ie->InvokeIndication_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 2); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - ABSINFORMATION
    if(ie->ABSInformation_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_absinformation(&ie->ABSInformation, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ABSINFORMATION,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - InvokeIndication
    if(ie->InvokeIndication_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_invokeindication(&ie->InvokeIndication, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_INVOKEINDICATION,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellinformation_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLINFORMATION_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->ABSInformation_present = false;
    ie->InvokeIndication_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ABSINFORMATION == ie_id) {
        if(liblte_x2ap_unpack_absinformation(ptr, &ie->ABSINFORMATION) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ABSInformation_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_INVOKEINDICATION == ie_id) {
        if(liblte_x2ap_unpack_invokeindication(ptr, &ie->InvokeIndication) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->InvokeIndication_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellInformation_Item STRUCT
********************************************************************************/
// Luca: fixed function name, add message_

LIBLTE_ERROR_ENUM liblte_x2ap_pack_message_cellinformation_item(
  LIBLTE_X2AP_MESSAGE_CELLINFORMATION_ITEM_STRUCT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - CELLINFORMATION_ITEM
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cellinformation_item(&ie->CellInformation_Item, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLINFORMATION_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_message_cellinformation_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLINFORMATION_ITEM_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLINFORMATION_ITEM == ie_id) {
        if(liblte_x2ap_unpack_cellinformation_item(ptr, &ie->CELLINFORMATION_ITEM) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List CellInformation_List DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellinformation_list(
  LIBLTE_X2AP_CELLINFORMATION_LIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cellinformation_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLINFORMATION_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellinformation_list(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLINFORMATION_LIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLINFORMATION_ITEM != ie_id) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(liblte_x2ap_unpack_cellinformation_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message LoadInformation STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_loadinformation(
  LIBLTE_X2AP_MESSAGE_LOADINFORMATION_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - LOADINFORMATION
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cellinformation_list(&ie->CellInformation, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLINFORMATION,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_loadinformation(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_LOADINFORMATION_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLINFORMATION == ie_id) {
        if(liblte_x2ap_unpack_cellinformation_list(ptr, &ie->CELLINFORMATION) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ServedCellsToModify_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_servedcellstomodify_item(
  LIBLTE_X2AP_SERVEDCELLSTOMODIFY_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext){
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    liblte_value_2_bits(ie->neighbour_info_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->cell_ID, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(liblte_x2ap_pack_servedcell_information(&ie->servedCellInfo, ptr) != LIBLTE_SUCCESS)
      //Luca: func TODO
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->neighbour_info_present)
      if(liblte_x2ap_pack_neighbour_information(&ie->neighbour_info, ptr) != LIBLTE_SUCCESS)
        //Luca: func TODO
        return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;

    err = LIBLTE_SUCCESS;

  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_servedcellstomodify_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SERVEDCELLSTOMODIFY_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    if(ie->ext){
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->neighbour_info_present = liblte_bits_2_value(ptr, 1);
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);

    if(liblte_x2ap_unpack_ecgi(ptr, &ie->cell_ID) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(liblte_x2ap_unpack_servedcell_information(ptr, &ie->servedCellInfo) != LIBLTE_SUCCESS)
      //Luca: this func is TODO
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->neighbour_info_present)
      if(liblte_x2ap_unpack_neighbour_information(ptr, &ie->neighbour_info) != LIBLTE_SUCCESS)
        //Luca: func TODO
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;

    err = LIBLTE_SUCCESS;

  }
  return err;
}



/*******************************************************************************
/* Protocol Message ServedCellsToModify_Item_Ext STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_servedcellstomodify_item_ext(
  LIBLTE_X2AP_MESSAGE_SERVEDCELLSTOMODIFY_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - LOADINFORMATION
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_deactivationindication(&ie->DeactivationIndication, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_DEACTIVATIONINDICATION,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_servedcellstomodify_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_SERVEDCELLSTOMODIFY_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_DEACTIVATIONINDICATION == ie_id) {
        if(liblte_x2ap_unpack_deactivationindication(ptr, &ie->DeactivationIndication) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List ServedCellsToModify DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256
LIBLTE_ERROR_ENUM liblte_x2ap_pack_servedcellstomodify(
  LIBLTE_X2AP_SERVEDCELLSTOMODIFY_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_servedcellstomodify_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_servedcellstomodify(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SERVEDCELLSTOMODIFY_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_servedcellstomodify_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List Old_ECGIs DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256

LIBLTE_ERROR_ENUM liblte_x2ap_pack_old_ecgis(
  LIBLTE_X2AP_OLD_ECGIS_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_ecgi(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_old_ecgis(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_OLD_ECGIS_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_ecgi(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ENBConfigurationUpdate STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_enbconfigurationupdate(
  LIBLTE_X2AP_MESSAGE_ENBCONFIGURATIONUPDATE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 5;
    if(!ie->ServedCellsToAdd_present)
      n_ie--;
    if(!ie->ServedCellsToModify_present)
      n_ie--;
    if(!ie->ServedCellsToDelete_present)
      n_ie--;
    if(!ie->GUGroupdIDToAddList_present)
      n_ie--;
    if(!ie->GUGroupIDToDeleteList_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - ServedCellstoAdd
    if(ie->ServedCellsToAdd_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_servedcells(&ie->ServedCellsToAdd, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_SERVEDCELLSTOADD,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - ServedCellstoModify
    if(ie->ServedCellsToModify_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_servedcellstomodify(&ie->ServedCellstoModify, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_SERVEDCELLSTOMODIFY,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - ServedCellstoDelete
    if(ie->ServedCellsToDelete_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_old_ecgis(&ie->ServedCellstoDelete, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_SERVEDCELLSTODELETE,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - GUGroupdIDToAddList
    if(ie->GUGroupdIDToAddList_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_gugroupidlist(&ie->GUGroupdIDToAddList, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_GUGROUPIDTOADDLIST,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - GUGroupIDToDeleteList
    if(ie->GUGroupIDToDeleteList_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_gugroupidlist(&ie->GUGroupIDToDeleteList, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_GUGROUPIDTODELETELIST,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_enbconfigurationupdate(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ENBCONFIGURATIONUPDATE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->ServedCellsToAdd_present = false;
    ie->ServedCellsToModify_present = false;
    ie->ServedCellsToDelete_present = false;
    ie->GUGroupdIDToAddList_present = false;
    ie->GUGroupIDToDeleteList_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_SERVEDCELLSTOADD == ie_id) {
        if(liblte_x2ap_unpack_servedcells(ptr, &ie->ServedCellstoAdd) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ServedCellsToAdd_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_SERVEDCELLSTOMODIFY == ie_id) {
        if(liblte_x2ap_unpack_servedcellstomodify(ptr, &ie->ServedCellstoModify) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ServedCellsToModify_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_SERVEDCELLSTODELETE == ie_id) {
        if(liblte_x2ap_unpack_old_ecgis(ptr, &ie->ServedCellstoDelete) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ServedCellsToDelete_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_GUGROUPIDTOADDLIST == ie_id) {
        if(liblte_x2ap_unpack_gugroupidlist(ptr, &ie->GUGroupdIDToAddList) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->GUGroupdIDToAddList_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_GUGROUPIDTODELETELIST == ie_id) {
        if(liblte_x2ap_unpack_gugroupidlist(ptr, &ie->GUGroupIDToDeleteList) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->GUGroupIDToDeleteList_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ENBConfigurationUpdateAcknowledge STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_enbconfigurationupdateacknowledge(
  LIBLTE_X2AP_MESSAGE_ENBCONFIGURATIONUPDATEACKNOWLEDGE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    if(!ie->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - ServedCellstoAdd
    if(ie->CriticalityDiagnostics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_enbconfigurationupdateacknowledge(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ENBCONFIGURATIONUPDATEACKNOWLEDGE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->CriticalityDiagnostics_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ENBConfigurationUpdateFailure STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_enbconfigurationupdatefailure(
  LIBLTE_X2AP_MESSAGE_ENBCONFIGURATIONUPDATEFAILURE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    if(!ie->TimeToWait_present)
      n_ie--;
    if(!ie->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 2); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;
    //IE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cause(&ie->Cause, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CAUSE,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - Time to wait
    if(ie->TimeToWait_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_timetowait(&ie->TimeToWait, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_TIMETOWAIT,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - Criticatily Diagnostics
    if(ie->CriticalityDiagnostics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_enbconfigurationupdatefailure(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ENBCONFIGURATIONUPDATEFAILURE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->CriticalityDiagnostics_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &ie->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->Cause_present = true;
      } else if(LIBLTE_X2AP_IE_ID_TIMETOWAIT == ie_id) {
        if(liblte_x2ap_unpack_timetowait(ptr, &ie->TimeToWait) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->TimeToWait_present = true;
      } else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CellToReport_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_celltoreport_item(
  LIBLTE_X2AP_CELLTOREPORT_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->cell_ID, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_celltoreport_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLTOREPORT_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_ecgi(ptr, &ie->cell_ID) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellToReport_Item_Ext STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_celltoreport_item_ext(
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_celltoreport_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);


    err = LIBLTE_SUCCESS;
  }
  return err;
}


/*******************************************************************************
/* Protocol Message CellToReport_Item STRUCT
********************************************************************************/
// Luca: fixed function name, add message_
LIBLTE_ERROR_ENUM liblte_x2ap_pack_message_celltoreport_item(
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_STRUCT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - CELLINFORMATION_ITEM
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_celltoreport_item(&ie->CellInformation_Item, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLTOREPORT_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}


LIBLTE_ERROR_ENUM liblte_x2ap_unpack_message_celltoreport_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLTOREPORT_ITEM == ie_id) {
        if(liblte_x2ap_unpack_celltoreport_item(ptr, &ie->CellToReport_Item) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List CellToReport_List DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256

LIBLTE_ERROR_ENUM liblte_x2ap_pack_celltoreport_list(
  LIBLTE_X2AP_CELLTOREPORT_LIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_celltoreport_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLTOREPORT_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_celltoreport_list(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLTOREPORT_LIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLTOREPORT_ITEM != ie_id) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(liblte_x2ap_unpack_celltoreport_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE ReportingPeriodicity ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_reportingperiodicity(
  LIBLTE_X2AP_REPORTINGPERIODICITY_ENUM_EXT                                *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_log_print("CauseMisc error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 3);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_reportingperiodicity(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REPORTINGPERIODICITY_ENUM_EXT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_log_print("CauseMisc error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_REPORTINGPERIODICITY_ENUM)liblte_bits_2_value(ptr, 3);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE PartialSuccessIndicator ENUMERATED
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_partialsuccessindicator(
  LIBLTE_X2AP_PARTIALSUCCESSINDICATOR_ENUM_EXT                                *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    if(ie->ext) {
      liblte_log_print("CauseMisc error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_partialsuccessindicator(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_PARTIALSUCCESSINDICATOR_ENUM_EXT                                *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    if(ie->ext) {
      liblte_log_print("CauseMisc error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_PARTIALSUCCESSINDICATOR_ENUM)liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ResourceStatusRequest STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_resourcestatusrequest(
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSREQUEST_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 7;
    if(!ie->ENB2_Measurement_ID_present)
      n_ie--;
    if(!ie->ReportCharacteristics_present)
      n_ie--;
    if(!ie->ReportingPeriodicity_present)
      n_ie--;
    if(!ie->PartialSuccessIndicator_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB1_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_Measurement_ID
    if(ie->ENB2_Measurement_ID_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_measurement_id(&ie->ENB2_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    //IE - Registration_Request
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_registration_request(&ie->Registration_Request, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_REGISTRATION_REQUEST,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - Report_Characteristics
    if(ie->ReportCharacteristics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_reportcharacteristics(&ie->Report_Characteristics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_REPORTCHARATERISTICS,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    //IE - Registration_Request
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_celltoreport_list(&ie->CellToReport, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLTOREPORT,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
      // ProtocolIE - ReportingPeriodicity
    if(ie->ReportingPeriodicity_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_reportingperiodicity(&ie->ReportingPeriodicity, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_REPORTINGPERIODICITY,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

     // ProtocolIE - PartialSuccess
    if(ie->PartialSuccessIndicator_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_partialsuccessindicator(&ie->PartialSuccessIndicator, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_PARTIALSUCCESSINDICATOR,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_resourcestatusrequest(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSREQUEST_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->ENB2_Measurement_ID_present = false;
    ie->ReportCharacteristics_present = false;
    ie->ReportingPeriodicity_present = false;
    ie->PartialSuccessIndicator_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB1_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB2_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ENB2_Measurement_ID_present = true;
      } else if(LIBLTE_X2AP_IE_ID_REGISTRATION_REQUEST == ie_id) {
        if(liblte_x2ap_unpack_registration_request(ptr, &ie->Registration_Request) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_REPORTCHARATERISTICS == ie_id) {
        if(liblte_x2ap_unpack_reportcharacteristics(ptr, &ie->ReportCharacteristics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ReportCharacteristics_present = true;
      } else if(LIBLTE_X2AP_IE_ID_CELLTOREPORT == ie_id) {
        if(liblte_x2ap_unpack_celltoreport_list(ptr, &ie->CellToReport) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_REPORTINGPERIODICITY == ie_id) {
        if(liblte_x2ap_unpack_reportingperiodicity(ptr, &ie->ReportingPeriodicity) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ReportingPeriodicity_present = true;
      } else if(LIBLTE_X2AP_IE_ID_PARTIALSUCCESSINDICATOR == ie_id) {
        if(liblte_x2ap_unpack_partialsuccessindicator(ptr, &ie->PartialSuccessIndicator) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->PartialSuccessIndicator_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MeasurementFailureCause_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementfailurecause_item(
  LIBLTE_X2AP_MEASUREMENTFAILURECAUSE_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_reportcharacteristics(&ie->measurementFailedReportCharacteristics, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(liblte_x2ap_pack_cause(&ie->cause, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementfailurecause_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MEASUREMENTFAILURECAUSE_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_reportcharacteristics(ptr, &ie->measurementFailedReportCharacteristics) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(liblte_x2ap_unpack_cause(ptr, &ie->cause) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message MeasurementFailureCause_Item_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementfailurecause_item_ext(
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementfailurecause_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);


    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message MeasurementFailureCause_Item STRUCT
********************************************************************************/
//Luca: change func name add message
LIBLTE_ERROR_ENUM liblte_x2ap_pack_message_measurementfailurecause_item(
  LIBLTE_X2AP_MESSAGE_MEASUREMENTFAILURECAUSE_ITEM_STRUCT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - CELLINFORMATION_ITEM
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_measurementfailurecause_item(&ie->MeasurementFailureCause_Item, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_MEASUREMENTFAILURECAUSE_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_message_measurementfailurecause_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_MEASUREMENTFAILURECAUSE_ITEM_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_MEASUREMENTFAILURECAUSE_ITEM == ie_id) {
        if(liblte_x2ap_unpack_measurementfailurecause_item(ptr, &ie->MeasurementFailureCause_Item) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List MeasurementFailureCause_List DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256

LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementfailurecause_list(
  LIBLTE_X2AP_MEASUREMENTFAILURECAUSE_LIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_measurementfailurecause_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_MEASUREMENTFAILURECAUSE_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementfailurecause_list(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MEASUREMENTFAILURECAUSE_LIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_MEASUREMENTFAILURECAUSE_ITEM != ie_id) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(liblte_x2ap_unpack_measurementfailurecause_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE MeasurementInitiationResult_Item SEQUENCE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementinitiationresult_item(
  LIBLTE_X2AP_MEASUREMENTINITIATIONRESULT_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->measurementFailureCause_List_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->cell_ID, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->measurementFailureCause_List_present)
      if(liblte_x2ap_pack_measurementfailurecause_list(&ie->measurementFailureCause_List, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementinitiationresult_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MEASUREMENTINITIATIONRESULT_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->measurementFailureCause_List_present = liblte_bits_2_value(ptr, 1);
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_ecgi(ptr, &ie->cell_ID) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->measurementFailureCause_List_present)
      if(liblte_x2ap_unpack_measurementfailurecause_list(ptr, &ie->measurementFailureCause_List) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message MeasurementInitiationresult_Item_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementinitiationresult_item_ext(
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementinitiationresult_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLTOREPORT_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);


    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message MeasurementInitiationResult_Item STRUCT
********************************************************************************/
//Luca: change func name add message

LIBLTE_ERROR_ENUM liblte_x2ap_pack_message_measurementinitiationresult_item(
  LIBLTE_X2AP_MESSAGE_MEASUREMENTINITIATIONRESULT_ITEM_STRUCT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - CELLINFORMATION_ITEM
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_measurementinitiationresult_item(&ie->MeasurementInitiationResult_Item, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_MEASUREMENTINITIATIONRESULT_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_message_measurementinitiationresult_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_MEASUREMENTINITIATIONRESULT_ITEM_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_MEASUREMENTINITIATIONRESULT_ITEM == ie_id) {
        if(liblte_x2ap_unpack_measurementinitiationresult_item(ptr, &ie->MeasurementInitiationResult_Item) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List MeasurementInitiationResult_List DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256
LIBLTE_ERROR_ENUM liblte_x2ap_pack_measurementinitiationresult_list(
  LIBLTE_X2AP_MEASUREMENTINITIATIONRESULT_LIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_measurementinitiationresult_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_MEASUREMENTINITIATIONRESULT_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_measurementinitiationresult_list(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MEASUREMENTINITIATIONRESULT_LIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_MEASUREMENTINITIATIONRESULT_ITEM != ie_id) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(liblte_x2ap_unpack_measurementinitiationresult_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ResourceStatusResponse STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_resourcestatusresponse(
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSRESPONSE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 4;
    if(!ie->CriticalityDiagnostics_present)
      n_ie--;
    if(!ie->MeasurementInitiationresult_List_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB1_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB2_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    //IE - CriticalityDiagnostics
    if(ie->CriticalityDiagnostics_present)
    {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    

    // ProtocolIE - Report_Characteristics
    if(ie->MeasurementInitiationresult_List_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_measurementinitiationresult_list(&ie->MeasurementInitiationResult_List, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_MEASUREMENTINITIATIONRESULT_LIST,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_resourcestatusresponse(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSRESPONSE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->CriticalityDiagnostics_present = false;
    ie->MeasurementInitiationresult_List_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB1_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB2_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      } else if(LIBLTE_X2AP_IE_ID_MEASUREMENTINITIATIONRESULT_LIST == ie_id) {
        if(liblte_x2ap_unpack_measurementinitiationresult_list(ptr, &ie->MeasurementInitiationResult_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->MeasurementInitiationresult_List_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CompleteFailureCauseInformation_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_completefailurecauseinformation_item(
  LIBLTE_X2AP_COMPLETEFAILURECAUSEINFORMATION_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->cell_ID, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(liblte_x2ap_pack_measurementfailurecause_list(&ie->measurementFailureCause_List, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_completefailurecauseinformation_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_COMPLETEFAILURECAUSEINFORMATION_ITEM_STRUCT                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_ecgi(ptr, &ie->cell_ID) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(liblte_x2ap_unpack_measurementfailurecause_list(ptr, &ie->measurementFailureCause_List) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CompleteFailureCauseInformation_Item_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_completefailurecauseinformation_item_ext(
  LIBLTE_X2AP_MESSAGE_COMPLETEFAILURECAUSEINFORMATION_ITEM_EXT_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_completefailurecauseinformation_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_COMPLETEFAILURECAUSEINFORMATION_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);


    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CompleteFailureCauseInformation_Item STRUCT
********************************************************************************/
//Luca: change func name add message

LIBLTE_ERROR_ENUM liblte_x2ap_pack_message_completefailurecauseinformation_item(
  LIBLTE_X2AP_MESSAGE_COMPLETEFAILURECAUSEINFORMATION_ITEM_STRUCT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - CELLINFORMATION_ITEM
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_completefailurecauseinformation_item(&ie->CompleteFailureCauseInformation_Item, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_COMPLETEFAILURECAUSEINFORMATION_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_message_completefailurecauseinformation_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_COMPLETEFAILURECAUSEINFORMATION_ITEM_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_COMPLETEFAILURECAUSEINFORMATION_ITEM == ie_id) {
        if(liblte_x2ap_unpack_completefailurecauseinformation_item(ptr, &ie->CompleteFailureCauseInformation_Item) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List CompleteFailureCauseInformation_List DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256
LIBLTE_ERROR_ENUM liblte_x2ap_pack_completefailurecauseinformation_list(
  LIBLTE_X2AP_COMPLETEFAILURECAUSEINFORMATION_LIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_completefailurecauseinformation_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_COMPLETEFAILURECAUSEINFORMATION_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_completefailurecauseinformation_list(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_COMPLETEFAILURECAUSEINFORMATION_LIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_COMPLETEFAILURECAUSEINFORMATION_ITEM != ie_id) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(liblte_x2ap_unpack_completefailurecauseinformation_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ResourceStatusFailure STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_resourcestatusfailure(
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSFAILURE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 5;
    if(!ie->CriticalityDiagnostics_present)
      n_ie--;
    if(!ie->CompleteFailureCauseInformation_List_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB1_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB2_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cause(&ie->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CAUSE,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    //IE - CriticalityDiagnostics
    if(ie->CriticalityDiagnostics_present)
    {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    
    // ProtocolIE - COMPLETEFAILURECAUSEINFORMATION_list
    if(ie->CompleteFailureCauseInformation_List_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_completefailurecauseinformation_list(&ie->CompleteFailureCauseInformation_List, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_COMPLETEFAILURECAUSEINFORMATION_LIST,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_resourcestatusfailure(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSFAILURE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    ie->CriticalityDiagnostics_present = false;
    ie->CompleteFailureCauseInformation_List_present = false;

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB1_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB2_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &ie->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      } else if(LIBLTE_X2AP_IE_ID_COMPLETEFAILURECAUSEINFORMATION_LIST == ie_id) {
        if(liblte_x2ap_unpack_completefailurecauseinformation_list(ptr, &ie->CompleteFailureCauseInformation_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CompleteFailureCauseInformation_List = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE CellMeasurementResult_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellmeasurementresult_item(
  LIBLTE_X2AP_CELLMEASUREMENTRESULT_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->hWLoadIndicator_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->s1TNLLoadIndicator_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->radioResourceStatus_present?1:0, ptr, 1);
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->cell_ID, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->s1TNLLoadIndicator_present)
      if(liblte_x2ap_pack_s1tnlloadindicator(&ie->s1TNLLoadIndicator, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->hWLoadIndicator_present)
      if(liblte_x2ap_pack_hwloadindicator(&ie->hWLoadIndicator, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->s1TNLLoadIndicator_present)
      if(liblte_x2ap_pack_s1tnlloadindicator(&ie->s1TNLLoadIndicator, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->radioResourceStatus_present)
      if(liblte_x2ap_pack_radioresourcestatus(&ie->radioResourceStatus, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellmeasurementresult_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLMEASUREMENTRESULT_ITEM_STRUCT                       *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->hWLoadIndicator_present = liblte_bits_2_value(ptr, 1);
    ie->s1TNLLoadIndicator_present = liblte_bits_2_value(ptr, 1);
    ie->radioResourceStatus_present = liblte_bits_2_value(ptr, 1);
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_ecgi(ptr, &ie->cell_ID) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;

    if(ie->hWLoadIndicator_present)
      if(liblte_x2ap_unpack_hwloadindicator(ptr, &ie->hWLoadIndicator) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->s1TNLLoadIndicator_present)
      if(liblte_x2ap_unpack_s1tnlloadindicator(ptr, &ie->s1TNLLoadIndicator) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->radioResourceStatus_present)
      if(liblte_x2ap_unpack_radioresourcestatus(ptr, &ie->radioResourceStatus) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellMeasurementResult_Item_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellmeasurementresult_item_ext(
  LIBLTE_X2AP_MESSAGE_CELLMEASUREMENTRESULT_ITEM_EXT_STRUCT            *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 2;
    if(ie->CompositeAvailableCapacityGroup_present)
      n_ie--;
    if(ie->ABS_Status_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 2);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;
    //IE - CompositeAvailableCapacityGroup
    if(ie->CompositeAvailableCapacityGroup_present)
    {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_compositeavailablecapacitygroup(&ie->CompositeAvailableCapacityGroup, &tmp_ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_COMPOSITEAVAILABLECAPACITYGROUP,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    //IE - ABS_status
    if(ie->ABS_Status_present)
    {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_abs_status(&ie->ABS_Status, &tmp_ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ABS_STATUS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellmeasurementresult_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLMEASUREMENTRESULT_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2);
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_COMPOSITEAVAILABLECAPACITYGROUP == ie_id) {
        if(liblte_x2ap_unpack_compositeavailablecapacitygroup(ptr, &ie->CompositeAvailableCapacityGroup) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CompositeAvailableCapacityGroup_present = true;
      } else if(LIBLTE_X2AP_IE_ID_ABS_STATUS == ie_id) {
        if(liblte_x2ap_unpack_abs_status(ptr, &ie->ABS_Status) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ABS_Status_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellMeasurementResult_Item STRUCT
********************************************************************************/
//Luca: change func name

LIBLTE_ERROR_ENUM liblte_x2ap_pack_message_cellmeasurementresult_item(
  LIBLTE_X2AP_MESSAGE_CELLMEASUREMENTRESULT_ITEM_STRUCT                 *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - CELLMEASUREMENTRESULT_ITEM
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cellmeasurementresult_item(&ie->CellMeasurementResult_Item, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLMEASUREMENTRESULT_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_message_cellmeasurementresult_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLMEASUREMENTRESULT_ITEM_STRUCT                 *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLMEASUREMENTRESULT_ITEM == ie_id) {
        if(liblte_x2ap_unpack_cellmeasurementresult_item(ptr, &ie->CellMeasurementResult_Item) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List CellMeasurementResult_List DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellmeasurementresult_list(
  LIBLTE_X2AP_CELLMEASUREMENTRESULT_LIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_cellmeasurementresult_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CELLMEASUREMENTRESULT_ITEM,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellmeasurementresult_list(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CELLMEASUREMENTRESULT_LIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CELLMEASUREMENTRESULT_ITEM != ie_id) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(liblte_x2ap_unpack_cellmeasurementresult_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ResourceStatusUpdate STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_resourcestatusupdate(
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSUPDATE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    liblte_value_2_bits(n_ie, ptr, 2); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB1_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_Measurement_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_measurement_id(&ie->ENB2_Measurement_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - CELLMEASUREMENTRESULT_LIST
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cellmeasurementresult_list(&ie->CellMeasurementResult, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CELLMEASUREMENTRESULT,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_resourcestatusupdate(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RESOURCESTATUSUPDATE_STRUCT                   *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB1_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_MEASUREMENT_ID == ie_id) {
        if(liblte_x2ap_unpack_measurement_id(ptr, &ie->ENB2_Measurement_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CELLMEASUREMENTRESULT == ie_id) {
        if(liblte_x2ap_unpack_cellmeasurementresult_list(ptr, &ie->CellMeasurementResult) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message PrivateMessage STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_privatemessage(
  LIBLTE_X2AP_MESSAGE_PRIVATEMESSAGE_STRUCT                    *ie,
  uint8_t                                                     **ptr)

{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_privatemessage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_PRIVATEMESSAGE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);


    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message MobilityChangeRequest STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mobilitychangerequest(
  LIBLTE_X2AP_MESSAGE_MOBILITYCHANGEREQUEST_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 5;
    if(ie->ENB1_Mobility_Parameters_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_CELL_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->ENB1_Cell_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_CELL_ID,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_CELL_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->ENB2_CELL_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_CELL_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB1_Mobility_Parameters
    if(ie->ENB1_Mobility_Parameters_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_mobilityparametersinformation_info(&ie->ENB1_Mobility_Parameters, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB1_MOBILITY_PARAMETERS,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;  
    }
    // ProtocolIE - ENB2_proposed_Mobility_Parameters
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_mobilityparametersinformation_info(&ie->ENB2_Proposed_Mobility_Parameters, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_PROPOSED_MOBILITY_PARAMETERS,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    // ProtocolIE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cause(&ie->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CAUSE,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mobilitychangerequest(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_MOBILITYCHANGEREQUEST_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_CELL_ID == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->ENB1_Cell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_CELL_ID == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->ENB2_Cell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB1_MOBILITY_PARAMETERS == ie_id) {
        if(liblte_x2ap_unpack_mobilityparametersinformation_info(ptr, &ie->ENB1_Mobility_Parameters) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ENB1_Mobility_Parameters_present = true;
      } else if(LIBLTE_X2AP_IE_ID_ENB2_PROPOSED_MOBILITY_PARAMETERS == ie_id) {
        if(liblte_x2ap_unpack_mobilityparametersinformation_info(ptr, &ie->ENB2_Proposed_Mobility_Parameters) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &ie->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}


  /*******************************************************************************
/* Protocol Message MobilityChangeAcknowledge STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mobilitychangeacknowledge(
  LIBLTE_X2AP_MESSAGE_MOBILITYCHANGEACKNOWLEDGE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    liblte_value_2_bits(n_ie, ptr, 2); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_Cell_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->ENB1_Cell_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_CELL_ID,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_Cell_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->ENB2_Cell_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_CELL_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - CriticalityDiagnostics
    if(ie->CriticalityDiagnostics_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
  
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mobilitychangeacknowledge(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_MOBILITYCHANGEACKNOWLEDGE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_CELL_ID == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->ENB1_Cell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_CELL_ID == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->ENB2_Cell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message MobilityChangeFailure STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_mobilitychangefailure(
  LIBLTE_X2AP_MESSAGE_MOBILITYCHANGEFAILURE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 5;
    if(ie->ENB2_Mobility_Parameters_Modification_Range_present)
      n_ie--;
    if(ie->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ENB1_CELL_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->ENB1_Cell_ID, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ENB1_CELL_ID,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_CELL_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->ENB2_CELL_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_CELL_ID,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    // ProtocolIE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cause(&ie->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CAUSE,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ENB2_Mobility_Parameters_Modification_Range
    if(ie->ENB2_Mobility_Parameters_Modification_Range_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_mobilityparametersmodificationrange_info(&ie->ENB2_Mobility_Parameters_Modification_Range, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_ENB2_MOBILITY_PARAMETERS_MODIFICATION_RANGE,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;  
    }
    
    // ProtocolIE - CriticalityDiagnostics
    if(ie->CriticalityDiagnostics_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mobilitychangefailure(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_MOBILITYCHANGEFAILURE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ENB1_CELL_ID == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->ENB1_Cell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_CELL_ID == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->ENB2_Cell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &ie->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_ENB2_MOBILITY_PARAMETERS_MODIFICATION_RANGE == ie_id) {
        if(liblte_x2ap_unpack_mobilityparametersmodificationrange_info(ptr, &ie->ENB2_Mobility_Parameters_Modification_Range) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ENB2_Mobility_Parameters_Modification_Range_present = true;
      } else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message RLFIndication STRUCT
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_rlfindication(
  LIBLTE_X2AP_MESSAGE_RLFINDICATION_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 7;
    if(!ie->ShortMAC_I_present)
      n_ie--;
    if(!ie->UE_RLF_Report_Container_present)
      n_ie--;
    if(!ie->RRCConnSetupIndicator_present)
      n_ie--;
    if(!ie->RRCConnReestabIndicator_present)
      n_ie--;

    liblte_value_2_bits(n_ie, ptr, 3); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - FAILURECELLPCI
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_pci(&ie->FailureCellPCI, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_FAILURECELLPCI,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - Re_establishmentCellECGI
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ecgi(&ie->Re_establishmentCellECGI, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_RE_ESTABLISHMENTCELLECGI,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - FailureCellCRNTI
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_crnti(&ie->FailureCellCRNTI, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_FAILURECELLCRNTI,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    // ProtocolIE - ShortMAC_I
    if(ie->ShortMAC_I_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_shortmac_i(&ie->ShortMAC_I, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_SHORTMAC_I,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - UE_RLF_Report_Container
    if(ie->UE_RLF_Report_Container_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_ue_rlf_report_container(&ie->UE_RLF_Report_Container, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_RLF_REPORT_CONTAINER,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - RRCConnSetupIndicator
    if(ie->RRCConnSetupIndicator_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_rrcconnsetupindicator(&ie->RRCConnSetupIndicator, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_RRCCONNSETUPINDICATOR,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }
    // ProtocolIE - RRCConnReestabIndicator
    if(ie->RRCConnReestabIndicator_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_rrcconnreestabindicator(&ie->RRCConnReestabIndicator, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_RRCCONNREESTABINDICATOR,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_rlfindication(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_RLFINDICATION_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 3); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_FAILURECELLPCI == ie_id) {
        if(liblte_x2ap_unpack_pci(ptr, &ie->FAILURECELLPCI) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_RE_ESTABLISHMENTCELLECGI == ie_id) {
        if(liblte_x2ap_unpack_ecgi(ptr, &ie->Re_establishmentCellECGI) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_FAILURECELLCRNTI == ie_id) {
        if(liblte_x2ap_unpack_crnti(ptr, &ie->FailureCellCRNTI) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_SHORTMAC_I == ie_id) {
        if(liblte_x2ap_unpack_shortmac_i(ptr, &ie->ShortMAC_I) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->ShortMAC_I_present = true;
      } else if(LIBLTE_X2AP_IE_ID_UE_RLF_REPORT_CONTAINER == ie_id) {
        if(liblte_x2ap_unpack_ue_rlf_report_container(ptr, &ie->UE_RLF_Report_Container) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->UE_RLF_Report_Container_present = true;
      } else if(LIBLTE_X2AP_IE_ID_RRCCONNSETUPINDICATOR == ie_id) {
        if(liblte_x2ap_unpack_rrcconnsetupindicator(ptr, &ie->RRCConnSetupIndicator) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->RRCConnSetupIndicator_present = true;
      } else if(LIBLTE_X2AP_IE_ID_RRCCONNREESTABINDICATOR == ie_id) {
        if(liblte_x2ap_unpack_rrcconnreestabindicator(ptr, &ie->RRCConnReestabIndicator) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->RRCConnReestabIndicator_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*-- **************************************************************
 *--
 *-- CELL ACTIVATION REQUEST
 *--
 *-- **************************************************************
 */

/*******************************************************************************
/* ProtocolIE ServedCellsToActivate_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_servedcellstoactivate_item(
  LIBLTE_X2AP_SERVEDCELLSTOACTIVATE_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->ecgi, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_servedcellstoactivate_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SERVEDCELLSTOACTIVATE_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_ecgi(ptr, &ie->ecgi) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ServedCellsToActivate_Item_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_servedcellstoactivate_item_ext(
  LIBLTE_X2AP_MESSAGE_SERVEDCELLSTOACTIVATE_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_servedcellstoactivate_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_SERVEDCELLSTOACTIVATE_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List ServedCellsToActivate DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256
LIBLTE_ERROR_ENUM liblte_x2ap_pack_servedcellstoactivate(
  LIBLTE_X2AP_SERVEDCELLSTOACTIVATE_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_servedcellstoactivate_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_servedcellstoactivate(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SERVEDCELLSTOACTIVATE_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_servedcellstoactivate_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellActivationRequest STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellactivationrequest(
  LIBLTE_X2AP_MESSAGE_CELLACTIVATIONREQUEST_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 1;
    liblte_value_2_bits(n_ie, ptr, 1); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ServedCellsToActivate
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_servedcellstoactivate(&ie->ServedCellsToActivate, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_SERVEDCELLSTOACTIVATE,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellactivationrequest(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLACTIVATIONREQUEST_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 1); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_SERVEDCELLSTOACTIVATE == ie_id) {
        if(liblte_x2ap_unpack_servedcellstoactivate(ptr, &ie->ServedCellsToActivate) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*-- **************************************************************
 *--
 *-- CELL ACTIVATION RESPONSE
 *--
 *-- **************************************************************
 */

/*******************************************************************************
/* ProtocolIE ActivatedCellList_Item SEQUENCE
********************************************************************************/

LIBLTE_ERROR_ENUM liblte_x2ap_pack_activatedcelllist_item(
  LIBLTE_X2AP_ACTIVATEDCELLLIST_ITEM_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    liblte_value_2_bits(ie->ext?1,0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_value_2_bits(ie->iE_Extensions_present?1:0, ptr, 1);
    if(liblte_x2ap_pack_ecgi(&ie->ecgi, ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_pack_protocolextensioncontainer(&ie->iE_Extensions, ptr) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_ENCODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_activatedcelllist_item(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ACTIVATEDCELLLIST_ITEM_STRUCT                         *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  if(ie != NULL && ptr != NULL)
  {
    ie->ext = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext)
    {
      liblte_log_print("CellToReport_Item error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    ie->iE_Extensions_present = liblte_bits_2_value(ptr, 1);
    if(liblte_x2ap_unpack_ecgi(ptr, &ie->ecgi) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_DECODE_FAIL;
    if(ie->iE_Extensions_present)
      if(liblte_x2ap_unpack_protocolextensioncontainer(ptr, &ie->iE_Extensions) != LIBLTE_SUCCESS)
        return LIBLTE_ERROR_DECODE_FAIL;
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message ActivatedCellList_Item_Ext STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_activatedcelllist_item_ext(
  LIBLTE_X2AP_MESSAGE_ACTIVATEDCELLLIST_ITEM_EXT_STRUCT             *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 0;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_activatedcelllist_item_ext(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_ACTIVATEDCELLLIST_ITEM_EXT_STRUCT             *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("E-RABToBeSwitchedDLItem-ExtIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Container List ActivatedCellList DYNAMIC SEQUENCE OF
********************************************************************************/
// lb:1, ub:256
LIBLTE_ERROR_ENUM liblte_x2ap_pack_activatedcelllist(
  LIBLTE_X2AP_ACTIVATEDCELLLIST_STRUCT                         *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    // Length
    liblte_value_2_bits(ie->len-1, ptr, 8);
    liblte_align_up_zero(ptr, 8);
    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_pack_activatedcelllist_item(&ie->buffer[i], &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_activatedcelllist(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ACTIVATEDCELLLIST_STRUCT                      *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;

    // Length
    ie->len = liblte_bits_2_value(ptr, 8) + 1;
    liblte_align_up(ptr, 8);
    if(ie->len > 32) {
      liblte_log_print("E_RABToBeSetupListBearerSUReq unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    uint32_t i;
    for(i=0;i<ie->len;i++) {
      if(liblte_x2ap_unpack_activatedcelllist_item(ptr, &ie->buffer[i]) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message CellActivationResponse STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellactivationresponse(
  LIBLTE_X2AP_MESSAGE_CELLACTIVATIONRESPONSE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 2;
    if(!ie->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 2); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - ActivatedCellList
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_activatedcelllist(&ie->ActivatedCellList, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_ACTIVATEDCELLLIST,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    //IE - CriticalityDiagnostics
    if(ie->CriticalityDiagnostics_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellactivationresponse(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLACTIVATIONRESPONSE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_ACTIVATEDCELLLIST == ie_id) {
        if(liblte_x2ap_unpack_activatedcelllist(ptr, &ie->ActivatedCellList) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*-- **************************************************************
 *--
 *-- CELL ACTIVATION FAILURE
 *--
 *-- **************************************************************
 */

/*******************************************************************************
/* Protocol Message CellActivationFailure STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_cellactivationfailure(
  LIBLTE_X2AP_MESSAGE_CELLACTIVATIONFAILURE_STRUCT                    *ie,
  uint8_t                                                     **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(ie->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 2;
    if(!ie->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 2); 

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    //IE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cause(&ie->Cause, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CAUSE,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    //IE - CriticalityDiagnostics
    if(ie->CriticalityDiagnostics_present)
    {
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_criticalitydiagnostics(&ie->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS)
      return LIBLTE_ERROR_ENCODE_FAIL;
    liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cellactivationfailure(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MESSAGE_CELLACTIVATIONFAILURE_STRUCT                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;


    // Extension
    ie->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(ie->ext) {
      liblte_log_print("ErrorIndicationIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 2); 

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &ie->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &ie->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        ie->CriticalityDiagnostics_present = true;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE-Field
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_protocolie_header(
  uint32_t                      len,
  uint32_t                      ie_id,
  LIBLTE_X2AP_CRITICALITY_ENUM  crit,
  uint8_t                     **ptr)
{
  liblte_value_2_bits(ie_id, ptr, 16); // ProtocolIE-ID
  liblte_value_2_bits(crit,  ptr, 2);  // Criticality
  liblte_align_up_zero(ptr, 8);
  if(len < 128) {                      // Length
    liblte_value_2_bits(0,   ptr, 1);
    liblte_value_2_bits(len, ptr, 7);
  } else if(len < 16383) {
    liblte_value_2_bits(1,   ptr, 1);
    liblte_value_2_bits(0,   ptr, 1);
    liblte_value_2_bits(len, ptr, 14);
  } else {
    // FIXME: Unlikely to have more than 16K of octets
  }

  return LIBLTE_SUCCESS;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_protocolie_header(
  uint8_t                     **ptr,
  uint32_t                     *ie_id,
  LIBLTE_X2AP_CRITICALITY_ENUM *crit,
  uint32_t                     *len)
{
  *ie_id = liblte_bits_2_value(ptr, 16);                               // ProtocolIE-ID
  *crit  = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);  // Criticality
  liblte_align_up(ptr, 8);
  if(0 == liblte_bits_2_value(ptr, 1)) {                               // Length
    *len = liblte_bits_2_value(ptr, 7);
  } else {
    if(0 == liblte_bits_2_value(ptr, 1)) {
      *len = liblte_bits_2_value(ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
    }
  }

  return LIBLTE_SUCCESS;
}

/*******************************************************************************
/* Protocol Message UEContextRelease STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_uecontextrelease(
  LIBLTE_X2AP_MESSAGE_UECONTEXTRELEASE_STRUCT                        *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("UEContextRelease-IEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 2;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - Old_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->Old_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - New_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->New_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_uecontextrelease(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_UECONTEXTRELEASE_STRUCT                 *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("UEContextRelease-IEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);
    bool old = false;

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id && !old) {
        /*if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->Old_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        old = true;
      } else      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id) {
        /*if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->New_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message SNStatusTransfer STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_snstatustransfer(
  LIBLTE_X2AP_MESSAGE_SNSTATUSTRANSFER_STRUCT                       *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("SNStatusTransferIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - Old_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->Old_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - New_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->New_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - E_RABs_SubjectToStatusTransfer_List
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_e_rabs_subjecttostatustransfer_list(&msg->E_RABs_SubjectToStatusTransfer_List, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_E_RABS_SUBJECTTOSTATUSTRANSFER_LIST,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_snstatustransfer(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_SNSTATUSTRANSFER_STRUCT                       *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("SNStatusTransferIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);
    bool old = false;

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id && !old) {
        /*if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->Old_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        old = true;
      } else      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id && old) {
        /*if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->New_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_E_RABS_SUBJECTTOSTATUSTRANSFER_LIST == ie_id) {
        /*if(liblte_x2ap_unpack_e_rabs_subjecttostatustransfer_list(ptr, &msg->E_RABs_SubjectToStatusTransfer_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message HandoverRequest STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_handoverrequest(
  LIBLTE_X2AP_MESSAGE_HANDOVERREQUEST_STRUCT                         *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("HandoverRequestIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 10;
    if(!msg->TraceActivation_present)
      n_ie--;
    if(!msg->SRVCCOperationPossible_present)
      n_ie--;
    if(!msg->CSGMembershipStatus_present)
      n_ie--;
    if(!msg->MobilityInformation_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - Old_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->Old_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_cause(&msg->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CAUSE,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - TargetCell_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ecgi(&msg->TargetCell_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_TARGETCELL_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - GUMMEI_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_gummei(&msg->GUMMEI_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_GUMMEI_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - UE_ContextInformation
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_contextinformation(&msg->UE_ContextInformation, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_CONTEXTINFORMATION,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - UE_HistoryInformation
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_historyinformation(&msg->UE_HistoryInformation, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_HISTORYINFORMATION,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - TraceActivation
    if(msg->TraceActivation_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_traceactivation(&msg->TraceActivation, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_TRACEACTIVATION,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - SRVCCOperationPossible
    if(msg->SRVCCOperationPossible_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_srvccoperationpossible(&msg->SRVCCOperationPossible, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_SRVCCOPERATIONPOSSIBLE,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - CSGMembershipStatus
    if(msg->CSGMembershipStatus_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_csgmembershipstatus(&msg->CSGMembershipStatus, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CSGMEMBERSHIPSTATUS,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - MobilityInformation
    if(msg->MobilityInformation_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_mobilityinformation(&msg->MobilityInformation, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_MOBILITYINFORMATION,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_handoverrequest(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_HANDOVERREQUEST_STRUCT                         *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->TraceActivation_present = false;
    msg->SRVCCOperationPossible_present = false;
    msg->CSGMembershipStatus_present = false;
    msg->MobilityInformation_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("HandoverRequestIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id) {
        /*if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->Old_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        /*if(liblte_x2ap_unpack_cause(ptr, &msg->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_TARGETCELL_ID == ie_id) {
        /*if(liblte_x2ap_unpack_ecgi(ptr, &msg->TargetCell_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_GUMMEI_ID == ie_id) {
        /*if(liblte_x2ap_unpack_gummei(ptr, &msg->GUMMEI_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_UE_CONTEXTINFORMATION == ie_id) {
        /*if(liblte_x2ap_unpack_ue_contextinformation(ptr, &msg->UE_ContextInformation) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_UE_HISTORYINFORMATION == ie_id) {
        /*if(liblte_x2ap_unpack_ue_historyinformation(ptr, &msg->UE_HistoryInformation) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_TRACEACTIVATION == ie_id) {
        /*if(liblte_x2ap_unpack_traceactivation(ptr, &msg->TraceActivation) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->TraceActivation_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_SRVCCOPERATIONPOSSIBLE == ie_id) {
        /*if(liblte_x2ap_unpack_srvccoperationpossible(ptr, &msg->SRVCCOperationPossible) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->SRVCCOperationPossible_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_CSGMEMBERSHIPSTATUS == ie_id) {
        /*if(liblte_x2ap_unpack_csgmembershipstatus(ptr, &msg->CSGMembershipStatus) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->CSGMembershipStatus_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_MOBILITYINFORMATION == ie_id) {
        /*if(liblte_x2ap_unpack_mobilityinformation(ptr, &msg->MobilityInformation) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->MobilityInformation_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message X2SetupRequest STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_x2setuprequest(
  LIBLTE_X2AP_MESSAGE_X2SETUPREQUEST_STRUCT                          *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("X2SetupRequestIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    if(!msg->GUGroupIDList_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - GlobalENB_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_globalenb_id(&msg->GlobalENB_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_GLOBALENB_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - ServedCells
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_servedcells(&msg->ServedCells, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_SERVEDCELLS,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - GUGroupIDList
    if(msg->GUGroupIDList_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_gugroupidlist(&msg->GUGroupIDList, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_GUGROUPIDLIST,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_x2setuprequest(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_X2SETUPREQUEST_STRUCT                          *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->GUGroupIDList_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("X2SetupRequestIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_GLOBALENB_ID == ie_id) {
        /*if(liblte_x2ap_unpack_globalenb_id(ptr, &msg->GlobalENB_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_SERVEDCELLS == ie_id) {
        /*if(liblte_x2ap_unpack_servedcells(ptr, &msg->ServedCells) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_GUGROUPIDLIST == ie_id) {
        /*if(liblte_x2ap_unpack_gugroupidlist(ptr, &msg->GUGroupIDList) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->GUGroupIDList_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message HandoverRequestAcknowledge STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_handoverrequestacknowledge(
  LIBLTE_X2AP_MESSAGE_HANDOVERREQUESTACKNOWLEDGE_STRUCT              *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("HandoverRequestAcknowledgeIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 6;
    if(!msg->E_RABs_NotAdmitted_List_present)
      n_ie--;
    if(!msg->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - Old_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->Old_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - New_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->New_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - E_RABs_Admitted_List
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_e_rabs_admitted_list(&msg->E_RABs_Admitted_List, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_E_RABS_ADMITTED_LIST,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - E_RABs_NotAdmitted_List
    if(msg->E_RABs_NotAdmitted_List_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_e_rab_list(&msg->E_RABs_NotAdmitted_List, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_E_RABS_NOTADMITTED_LIST,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - TargeteNBtoSource_eNBTransparentContainer
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_targetenbtosource_enbtransparentcontainer(&msg->TargeteNBtoSource_eNBTransparentContainer, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - CriticalityDiagnostics
    if(msg->CriticalityDiagnostics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_criticalitydiagnostics(&msg->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_handoverrequestacknowledge(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_HANDOVERREQUESTACKNOWLEDGE_STRUCT              *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->E_RABs_NotAdmitted_List_present = false;
    msg->CriticalityDiagnostics_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("HandoverRequestAcknowledgeIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);

    // Unpack ProtocolIE Fields
    bool old = false;

    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id && !old) {
        if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->Old_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        old = true;
      } else      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id && old) {
        if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->New_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_E_RABS_ADMITTED_LIST == ie_id) {
        if(liblte_x2ap_unpack_e_rabs_admitted_list(ptr, &msg->E_RABs_Admitted_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_E_RABS_NOTADMITTED_LIST == ie_id) {
        if(liblte_x2ap_unpack_e_rab_list(ptr, &msg->E_RABs_NotAdmitted_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->E_RABs_NotAdmitted_List_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER == ie_id) {
        if(liblte_x2ap_unpack_targetenbtosource_enbtransparentcontainer(ptr, &msg->TargeteNBtoSource_eNBTransparentContainer) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &msg->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->CriticalityDiagnostics_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message X2SetupResponse STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_x2setupresponse(
  LIBLTE_X2AP_MESSAGE_X2SETUPRESPONSE_STRUCT                         *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("X2SetupResponseIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 4;
    if(!msg->GUGroupIDList_present)
      n_ie--;
    if(!msg->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

	// ProtocolIE - GlobalENB_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_globalenb_id(&msg->GlobalENB_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_GLOBALENB_ID,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

	// ProtocolIE - ServedCells
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_servedcells(&msg->ServedCells, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_SERVEDCELLS,
                                          LIBLTE_X2AP_CRITICALITY_REJECT,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - GUGroupIDList
    if(msg->GUGroupIDList_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_gugroupidlist(&msg->GUGroupIDList, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_GUGROUPIDLIST,
                                            LIBLTE_X2AP_CRITICALITY_REJECT,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - CriticalityDiagnostics
    if(msg->CriticalityDiagnostics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_criticalitydiagnostics(&msg->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_x2setupresponse(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_X2SETUPRESPONSE_STRUCT                         *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->GUGroupIDList_present = false;
    msg->CriticalityDiagnostics_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("X2SetupResponseIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_GLOBALENB_ID == ie_id) {
        /*if(liblte_x2ap_unpack_globalenb_id(ptr, &msg->GlobalENB_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_SERVEDCELLS == ie_id) {
        /*if(liblte_x2ap_unpack_servedcells(ptr, &msg->ServedCells) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_GUGROUPIDLIST == ie_id) {
        /*if(liblte_x2ap_unpack_gugroupidlist(ptr, &msg->GUGroupIDList) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->GUGroupIDList_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        /*if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &msg->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->CriticalityDiagnostics_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message HandoverPreparationFailure STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_handoverpreparationfailure(
  LIBLTE_X2AP_MESSAGE_HANDOVERPREPARATIONFAILURE_STRUCT              *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("HandoverPreparationFailureIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    if(!msg->CriticalityDiagnostics_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - Old_eNB_UE_X2AP_ID
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_ue_x2ap_id(&msg->Old_eNB_UE_X2AP_ID, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_UE_X2AP_ID,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    /*if(liblte_x2ap_pack_cause(&msg->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }*/
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CAUSE,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - CriticalityDiagnostics
    if(msg->CriticalityDiagnostics_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_criticalitydiagnostics(&msg->CriticalityDiagnostics, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_handoverpreparationfailure(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_HANDOVERPREPARATIONFAILURE_STRUCT              *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->CriticalityDiagnostics_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("HandoverPreparationFailureIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_UE_X2AP_ID == ie_id) {
        /*if(liblte_x2ap_unpack_ue_x2ap_id(ptr, &msg->Old_eNB_UE_X2AP_ID) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        /*if(liblte_x2ap_unpack_cause(ptr, &msg->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_CRITICALITYDIAGNOSTICS == ie_id) {
        /*if(liblte_x2ap_unpack_criticalitydiagnostics(ptr, &msg->CriticalityDiagnostics) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->CriticalityDiagnostics_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* Protocol Message X2SetupFailure STRUCT
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_x2setupfailure(
  LIBLTE_X2AP_MESSAGE_X2SETUPFAILURE_STRUCT                          *msg,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {

    // Extension
    liblte_value_2_bits(msg->ext?1:0, ptr, 1);
    liblte_align_up_zero(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("X2SetupFailureIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // No. of ProtocolIE
    uint32_t n_ie = 3;
    if(!msg->TimeToWait_present)
      n_ie--;
    if(!msg->GUGroupIDList_present)
      n_ie--;
    liblte_value_2_bits(n_ie, ptr, 16);

    // Temp container for IEs
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t              *tmp_ptr;

    // ProtocolIE - Cause
    tmp_msg.reset();
    tmp_ptr = tmp_msg.msg;
    if(liblte_x2ap_pack_cause(&msg->Cause, &tmp_ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    liblte_align_up_zero(&tmp_ptr, 8);
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
    if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                          LIBLTE_X2AP_IE_ID_CAUSE,
                                          LIBLTE_X2AP_CRITICALITY_IGNORE,
                                          ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    // ProtocolIE - TimeToWait
    if(msg->TimeToWait_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_timetowait(&msg->TimeToWait, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_TIMETOWAIT,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    // ProtocolIE - GUGroupIDList
    if(msg->GUGroupIDList_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      if(liblte_x2ap_pack_gugroupidlist(&msg->GUGroupIDList, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      liblte_align_up_zero(&tmp_ptr, 8);
      tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;
      if(liblte_x2ap_pack_protocolie_header(tmp_msg.N_bits / 8,
                                            LIBLTE_X2AP_IE_ID_GUGROUPIDLIST,
                                            LIBLTE_X2AP_CRITICALITY_IGNORE,
                                            ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
      memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
      *ptr += tmp_msg.N_bits;
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_x2setupfailure(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_MESSAGE_X2SETUPFAILURE_STRUCT                          *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg != NULL &&
     ptr != NULL)
  {
    LIBLTE_X2AP_CRITICALITY_ENUM crit;
    uint32_t ie_id;
    uint32_t len;
    uint32_t n_ie;
    uint32_t i;

    // Set booleans
    msg->TimeToWait_present = false;
    msg->GUGroupIDList_present = false;

    // Extension
    msg->ext  = liblte_bits_2_value(ptr, 1);
    liblte_align_up(ptr, 8);
    if(msg->ext) {
      liblte_x2ap_log_print("X2SetupFailureIEs error: X2AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // No. of ProtocolIE-Container
    n_ie = liblte_bits_2_value(ptr, 16);

    // Unpack ProtocolIE Fields
    for(i=0;i<n_ie;i++) {
      if(liblte_x2ap_unpack_protocolie_header(ptr, &ie_id, &crit, &len) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
      if(LIBLTE_X2AP_IE_ID_CAUSE == ie_id) {
        if(liblte_x2ap_unpack_cause(ptr, &msg->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_TIMETOWAIT == ie_id) {
        if(liblte_x2ap_unpack_timetowait(ptr, &msg->TimeToWait) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->TimeToWait_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_GUGROUPIDLIST == ie_id) {
        if(liblte_x2ap_unpack_gugroupidlist(ptr, &msg->GUGroupIDList) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }
        liblte_align_up(ptr, 8);
        msg->GUGroupIDList_present = true;
      } 
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* InitiatingMessage CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_initiatingmessage(
  LIBLTE_X2AP_INITIATINGMESSAGE_STRUCT *msg,
  uint8_t                             **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg                                      != NULL &&
     ptr                                      != NULL)
  { 
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t *tmp_ptr = tmp_msg.msg;

    // Message
    if(msg->choice_type == LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_X2SETUPREQUEST) {
      if(liblte_x2ap_pack_x2setuprequest(&msg->choice.X2SetupRequest, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } else    if(msg->choice_type == LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_HANDOVERREQUEST) {
      if(liblte_x2ap_pack_handoverrequest(&msg->choice.HandoverRequest, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } else    if(msg->choice_type == LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_SNSTATUSTRANSFER) {
      if(liblte_x2ap_pack_snstatustransfer(&msg->choice.SNStatusTransfer, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } else    if(msg->choice_type == LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_UECONTEXTRELEASE) {
      if(liblte_x2ap_pack_uecontextrelease(&msg->choice.UEContextRelease, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } 
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;

    // Procedure code
    liblte_value_2_bits(msg->procedureCode, ptr, 8);

    // Criticality
    LIBLTE_X2AP_CRITICALITY_ENUM crit = liblte_x2ap_procedure_criticality[msg->procedureCode];
    liblte_value_2_bits(crit, ptr, 2);
    liblte_align_up_zero(ptr, 8);

    // Length
    uint32_t len = (tmp_msg.N_bits + 7) / 8;
    if(len < 128) {
      liblte_value_2_bits(0,   ptr, 1);
      liblte_value_2_bits(len, ptr, 7);
    } else if(len < 16383) {
      liblte_value_2_bits(1,   ptr, 1);
      liblte_value_2_bits(0,   ptr, 1);
      liblte_value_2_bits(len, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
    }

    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_initiatingmessage(
  uint8_t                             **ptr,
  LIBLTE_X2AP_INITIATINGMESSAGE_STRUCT *msg)
{  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg                                      != NULL &&
     ptr                                      != NULL)
  {
    // Procedure code
    msg->procedureCode  = liblte_bits_2_value(ptr, 8);

    // Criticality
    msg->criticality    = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);

    // Length
    uint32_t len = 0;
    if(0 == liblte_bits_2_value(ptr, 1)) {
      len = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        len = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
      }
    }

    // Message
    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_X2SETUP) {
      msg->choice_type = LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_X2SETUPREQUEST;
      if(liblte_x2ap_unpack_x2setuprequest(ptr, &msg->choice.X2SetupRequest) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } else    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_HANDOVERPREPARATION) {
      msg->choice_type = LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_HANDOVERREQUEST;
      if(liblte_x2ap_unpack_handoverrequest(ptr, &msg->choice.HandoverRequest) != LIBLTE_SUCCESS) 
      {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } else    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_SNSTATUSTRANSFER) {
      msg->choice_type = LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_SNSTATUSTRANSFER;
      if(liblte_x2ap_unpack_snstatustransfer(ptr, &msg->choice.SNStatusTransfer) != LIBLTE_SUCCESS) 
      {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } else    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_UECONTEXTRELEASE) {
      msg->choice_type = LIBLTE_X2AP_INITIATINGMESSAGE_CHOICE_UECONTEXTRELEASE;
      if(liblte_x2ap_unpack_uecontextrelease(ptr, &msg->choice.UEContextRelease) != LIBLTE_SUCCESS) 
      {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } 
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* SuccessfulOutcome CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_successfuloutcome(
  LIBLTE_X2AP_SUCCESSFULOUTCOME_STRUCT *msg,
  uint8_t                             **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg                                      != NULL &&
     ptr                                      != NULL)
  { 
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t *tmp_ptr = tmp_msg.msg;

    // Message
    if(msg->choice_type == LIBLTE_X2AP_SUCCESSFULOUTCOME_CHOICE_HANDOVERREQUESTACKNOWLEDGE) {
      if(liblte_x2ap_pack_handoverrequestacknowledge(&msg->choice.HandoverRequestAcknowledge, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } else    if(msg->choice_type == LIBLTE_X2AP_SUCCESSFULOUTCOME_CHOICE_X2SETUPRESPONSE) {
      if(liblte_x2ap_pack_x2setupresponse(&msg->choice.X2SetupResponse, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } 
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;

    // Procedure code
    liblte_value_2_bits(msg->procedureCode, ptr, 8);

    // Criticality
    LIBLTE_X2AP_CRITICALITY_ENUM crit = liblte_x2ap_procedure_criticality[msg->procedureCode];
    liblte_value_2_bits(crit, ptr, 2);
    liblte_align_up_zero(ptr, 8);

    // Length
    uint32_t len = (tmp_msg.N_bits + 7) / 8;
    if(len < 128) {
      liblte_value_2_bits(0,   ptr, 1);
      liblte_value_2_bits(len, ptr, 7);
    } else if(len < 16383) {
      liblte_value_2_bits(1,   ptr, 1);
      liblte_value_2_bits(0,   ptr, 1);
      liblte_value_2_bits(len, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
    }

    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_successfuloutcome(
  uint8_t                             **ptr,
  LIBLTE_X2AP_SUCCESSFULOUTCOME_STRUCT *msg)
{  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg                                      != NULL &&
     ptr                                      != NULL)
  {
    // Procedure code
    msg->procedureCode  = liblte_bits_2_value(ptr, 8);

    // Criticality
    msg->criticality    = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);

    // Length
    uint32_t len = 0;
    if(0 == liblte_bits_2_value(ptr, 1)) {
      len = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        len = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
      }
    }

    // Message
    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_HANDOVERPREPARATION) {
      msg->choice_type = LIBLTE_X2AP_SUCCESSFULOUTCOME_CHOICE_HANDOVERREQUESTACKNOWLEDGE;
      if(liblte_x2ap_unpack_handoverrequestacknowledge(ptr, &msg->choice.HandoverRequestAcknowledge) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } else    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_X2SETUP) {
      msg->choice_type = LIBLTE_X2AP_SUCCESSFULOUTCOME_CHOICE_X2SETUPRESPONSE;
      if(liblte_x2ap_unpack_x2setupresponse(ptr, &msg->choice.X2SetupResponse) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* UnsuccessfulOutcome CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_unsuccessfuloutcome(
  LIBLTE_X2AP_UNSUCCESSFULOUTCOME_STRUCT *msg,
  uint8_t                               **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg                                      != NULL &&
     ptr                                      != NULL)
  { 
    LIBLTE_BIT_MSG_STRUCT tmp_msg;
    uint8_t *tmp_ptr = tmp_msg.msg;

    // Message
    if(msg->choice_type == LIBLTE_X2AP_UNSUCCESSFULOUTCOME_CHOICE_HANDOVERPREPARATIONFAILURE) {
      if(liblte_x2ap_pack_handoverpreparationfailure(&msg->choice.HandoverPreparationFailure, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } else    if(msg->choice_type == LIBLTE_X2AP_UNSUCCESSFULOUTCOME_CHOICE_X2SETUPFAILURE) {
      if(liblte_x2ap_pack_x2setupfailure(&msg->choice.X2SetupFailure, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } 
    tmp_msg.N_bits = tmp_ptr - tmp_msg.msg;

    // Procedure code
    liblte_value_2_bits(msg->procedureCode, ptr, 8);

    // Criticality
    LIBLTE_X2AP_CRITICALITY_ENUM crit = liblte_x2ap_procedure_criticality[msg->procedureCode];
    liblte_value_2_bits(crit, ptr, 2);
    liblte_align_up_zero(ptr, 8);

    // Length
    uint32_t len = (tmp_msg.N_bits + 7) / 8;
    if(len < 128) {
      liblte_value_2_bits(0,   ptr, 1);
      liblte_value_2_bits(len, ptr, 7);
    } else if(len < 16383) {
      liblte_value_2_bits(1,   ptr, 1);
      liblte_value_2_bits(0,   ptr, 1);
      liblte_value_2_bits(len, ptr, 14);
    } else {
      // FIXME: Unlikely to have more than 16K of octets
    }

    memcpy(*ptr, tmp_msg.msg, tmp_msg.N_bits);
    *ptr += tmp_msg.N_bits;

    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_unsuccessfuloutcome(
  uint8_t                               **ptr,
  LIBLTE_X2AP_UNSUCCESSFULOUTCOME_STRUCT *msg)
{  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(msg                                      != NULL &&
     ptr                                      != NULL)
  {
    // Procedure code
    msg->procedureCode  = liblte_bits_2_value(ptr, 8);

    // Criticality
    msg->criticality    = (LIBLTE_X2AP_CRITICALITY_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);

    // Length
    uint32_t len = 0;
    if(0 == liblte_bits_2_value(ptr, 1)) {
      len = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        len = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of octets
      }
    }

    // Message
    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_HANDOVERPREPARATION) {
      msg->choice_type = LIBLTE_X2AP_UNSUCCESSFULOUTCOME_CHOICE_HANDOVERPREPARATIONFAILURE;
      if(liblte_x2ap_unpack_handoverpreparationfailure(ptr, &msg->choice.HandoverPreparationFailure) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } else    if(msg->procedureCode == LIBLTE_X2AP_PROC_ID_X2SETUP) {
      msg->choice_type = LIBLTE_X2AP_UNSUCCESSFULOUTCOME_CHOICE_X2SETUPFAILURE;
      if(liblte_x2ap_unpack_x2setupfailure(ptr, &msg->choice.X2SetupFailure) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    } 
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* X2AP_PDU CHOICE
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_x2ap_pdu(
  LIBLTE_X2AP_X2AP_PDU_STRUCT *x2ap_pdu,
  LIBLTE_BYTE_MSG_STRUCT      *msg)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  LIBLTE_BIT_MSG_STRUCT bit_msg;

  if(x2ap_pdu                                 != NULL &&
     msg                                      != NULL)
  {
    uint8_t *p    = bit_msg.msg;
    uint8_t **ptr = &p;

    // Extension
    liblte_value_2_bits(x2ap_pdu->ext?1:0, ptr, 1);

    // Message choice
    liblte_value_2_bits(x2ap_pdu->choice_type, ptr, 2);
    liblte_align_up_zero(ptr, 8);

    // Message
    if(LIBLTE_X2AP_X2AP_PDU_CHOICE_INITIATINGMESSAGE == x2ap_pdu->choice_type) {
      if(liblte_x2ap_pack_initiatingmessage(&x2ap_pdu->choice.initiatingMessage, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    } else if(LIBLTE_X2AP_X2AP_PDU_CHOICE_SUCCESSFULOUTCOME == x2ap_pdu->choice_type) {
      if(liblte_x2ap_pack_successfuloutcome(&x2ap_pdu->choice.successfulOutcome, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
     }else if(LIBLTE_X2AP_X2AP_PDU_CHOICE_UNSUCCESSFULOUTCOME == x2ap_pdu->choice_type) {
      if(liblte_x2ap_pack_unsuccessfuloutcome(&x2ap_pdu->choice.unsuccessfulOutcome, ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }
    }

    liblte_align_up_zero(ptr, 8);
    bit_msg.N_bits += (*ptr - bit_msg.msg);

    liblte_pack(&bit_msg, msg);
    err = LIBLTE_SUCCESS;

  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_x2ap_pdu(
  LIBLTE_BYTE_MSG_STRUCT      *msg,
  LIBLTE_X2AP_X2AP_PDU_STRUCT *x2ap_pdu)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  LIBLTE_BIT_MSG_STRUCT bit_msg;

  if(x2ap_pdu                                 != NULL &&
     msg                                      != NULL)
  {
    liblte_unpack(msg, &bit_msg);

    uint8_t *p    = bit_msg.msg;
    uint8_t **ptr = &p;

    // Extension
    x2ap_pdu->ext = liblte_bits_2_value(ptr, 1);

    // Message choice
    x2ap_pdu->choice_type = (LIBLTE_X2AP_X2AP_PDU_CHOICE_ENUM)liblte_bits_2_value(ptr, 2);
    liblte_align_up(ptr, 8);

    // Message
    if(LIBLTE_X2AP_X2AP_PDU_CHOICE_INITIATINGMESSAGE == x2ap_pdu->choice_type) {
      if(liblte_x2ap_unpack_initiatingmessage(ptr, &x2ap_pdu->choice.initiatingMessage) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }else if(LIBLTE_X2AP_X2AP_PDU_CHOICE_SUCCESSFULOUTCOME == x2ap_pdu->choice_type) {
      if(liblte_x2ap_unpack_successfuloutcome(ptr, &x2ap_pdu->choice.successfulOutcome) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }else if(LIBLTE_X2AP_X2AP_PDU_CHOICE_UNSUCCESSFULOUTCOME == x2ap_pdu->choice_type) {
      if(liblte_x2ap_unpack_unsuccessfuloutcome(ptr, &x2ap_pdu->choice.unsuccessfulOutcome) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_DECODE_FAIL;
      }
    }

    err = LIBLTE_SUCCESS;
  }
  return err;
}
