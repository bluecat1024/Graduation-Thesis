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
    liblte_value_2_bits(0, ptr, (2*8)-16);
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
    ie->local = (uint16_t)liblte_bits_2_value(ptr, 2.0*8);
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
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Choice type
    liblte_value_2_bits(ie->choice_type, ptr, 1);
        // Choice
 if(ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_LOCAL) {
      if(liblte_x2ap_pack_local(&ie->choice.local, ptr) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_ENCODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_GLOBAL) {
      } 
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 LIBLTE_ERROR_ENUM liblte_x2ap_unpack_privateie_id(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PRIVATEIE_ID_STRUCT                                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
   if(ie  != NULL &&
     ptr != NULL)
  {
    // Choice type
    ie->choice_type = (LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_ENUM)liblte_bits_2_value(ptr, 1);
        // Choice
 if(ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_LOCAL) {
      if(liblte_x2ap_unpack_local(ptr, &ie->choice.local) != LIBLTE_SUCCESS) {
      return LIBLTE_ERROR_DECODE_FAIL;
    }
    } else if(ie->choice_type == LIBLTE_X2AP_PRIVATEIE_ID_CHOICE_GLOBAL) {
      } 
    err = LIBLTE_SUCCESS;
  }
  return err;
}
 /*******************************************************************************
/* ProtocolIE ProtocolExtensionID INTEGER
********************************************************************************/
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
      liblte_log_print("ProtocolIE_Container pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("ProtocolIE_Container unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
     if(liblte_x2ap_pack_protocolextensionid(&ie->id, ptr) != LIBLTE_SUCCESS) {
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
     if(liblte_x2ap_unpack_protocolextensionid(ptr, &ie->id) != LIBLTE_SUCCESS) {
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
      liblte_log_print("ProtocolExtensionContainer pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("ProtocolExtensionContainer unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("ProtocolIE_ContainerPair pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("ProtocolIE_ContainerPair unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("ProtocolIE_ContainerList pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->len = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->len = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of bits
      }
    }
    if(ie->len > 32) {
      liblte_log_print("ProtocolIE_ContainerPairList unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("ProtocolIE_ContainerPairList pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
    if(0 == liblte_bits_2_value(ptr, 1)) {
      ie->len = liblte_bits_2_value(ptr, 7);
    } else {
      if(0 == liblte_bits_2_value(ptr, 1)) {
        ie->len = liblte_bits_2_value(ptr, 14);
      } else {
        // FIXME: Unlikely to have more than 16K of bits
      }
    }
    if(ie->len > 32) {
      liblte_log_print("ProtocolIE_ContainerPairList unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("PrivateIE_Container pack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
      liblte_log_print("PrivateIE_Container unpack error - max supported dynamic sequence length = 32, ie->len = %d\n", ie->len);
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
	 	liblte_value_2_bits(ie->EARFCNExtension, ptr, 16);
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
		ie->EARFCNExtension = (uint16_t)liblte_bits_2_value(ptr, 16);
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
      liblte_log_print("ie->E_RAB_ID error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("ie->E_RAB_ID error: S1AP ASN extensions not currently supported\n");
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
    // Integer - ie->HFNModified
    // lb:0, ub:131071
    // Range > 65536 - encoded based on value
    {
      uint32_t n_bits   = floor(log2(ie->Measurement_ID-0)+1);
      uint32_t n_octets = (n_bits+7)/8;
      liblte_value_2_bits(n_octets-1, ptr, 2);
      liblte_align_up_zero(ptr, 8);
      liblte_value_2_bits(0, ptr, (n_octets*8)-n_bits);
      liblte_value_2_bits(ie->Measurement_ID-0, ptr, n_bits);
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
    // Integer - ie->HFNModified
    // lb:0, ub:131071
    // Range > 65536 - encoded based on value
    {
      uint32_t n_octets = liblte_bits_2_value(ptr, 2) + 1;
      liblte_align_up(ptr, 8);
      ie->Measurement_ID = liblte_bits_2_value(ptr, n_octets*8) + 0;
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
    liblte_value_2_bits(ie->nextHopChainingCount, ptr, 3);
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
    ie->nextHopChainingCount = (uint8_t)liblte_bits_2_value(ptr, 3);
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
    liblte_value_2_bits(0, ptr, (1*8)-12);
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
    liblte_value_2_bits(0, ptr, (1*8)-15);
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
    // Integer - ie->QCI
    // lb:0, ub:255
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
    // Integer - ie->QCI
    // lb:0, ub:255
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
    // Integer - ie->QCI
    // lb:0, ub:255
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
    // Integer - ie->QCI
    // lb:0, ub:255
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
    liblte_value_2_bits(0, ptr, (1*8)-12);
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
/* ProtocolIE UE_X2AP_ID INTEGER
********************************************************************************/
typedef struct{
uint64_t UE_X2AP_ID;
}LIBLTE_X2AP_UE_X2AP_ID_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ue_x2ap_id(
  LIBLTE_X2AP_UE_X2AP_ID_STRUCT                  *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ue_x2ap_id(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UE_X2AP_ID_STRUCT                  *ie);

/*******************************************************************************
/* ProtocolIE UE_X2AP_ID INTEGER
********************************************************************************/
typedef struct{
uint16_t UE_X2AP_ID;
}LIBLTE_X2AP_UE_X2AP_ID_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ue_x2ap_id(
  LIBLTE_X2AP_UE_X2AP_ID_STRUCT                  *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ue_x2ap_id(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UE_X2AP_ID_STRUCT                  *ie);


/*******************************************************************************
/* ProtocolIE UL_GBR_PRB_usage INTEGER
********************************************************************************/
typedef struct{
uint16_t UL_GBR_PRB_usage;
}LIBLTE_X2AP_UL_GBR_PRB_USAGE_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_gbr_prb_usage(
  LIBLTE_X2AP_UL_GBR_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_gbr_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_GBR_PRB_USAGE_STRUCT                            *ie);

/*******************************************************************************
/* ProtocolIE UL_non_GBR_PRB_usage INTEGER
********************************************************************************/
typedef struct{
uint16_t UL_non_GBR_PRB_usage;
}LIBLTE_X2AP_UL_NON_GBR_PRB_USAGE_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_non_gbr_prb_usage(
  LIBLTE_X2AP_UL_NON_GBR_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_non_gbr_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_NON_GBR_PRB_USAGE_STRUCT                            *ie);

/*******************************************************************************
/* ProtocolIE UL_Total_PRB_usage INTEGER
********************************************************************************/
typedef struct{
uint16_t UL_Total_PRB_usage;
}LIBLTE_X2AP_UL_TOTAL_PRB_USAGE_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_total_prb_usage(
  LIBLTE_X2AP_UL_TOTAL_PRB_USAGE_STRUCT                            *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_total_prb_usage(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_TOTAL_PRB_USAGE_STRUCT                            *ie);

/*******************************************************************************
/* ProtocolIE CRNTI STATIC BIT STRING
********************************************************************************/
#define LIBLTE_X2AP_CRNTI_BIT_STRING_LEN 16
typedef struct{
  uint8_t  buffer[16];
}LIBLTE_X2AP_CRNTI_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_crnti(
  LIBLTE_X2AP_CRNTI_STRUCT                               *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_crnti(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CRNTI_STRUCT                               *ie);

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
      liblte_log_print("EncryptionAlgorithms error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("EncryptionAlgorithms error: S1AP ASN extensions not currently supported\n");
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
#define LIBLTE_X2AP_EUTRANCELLIDENTIFIER_BIT_STRING_LEN 28
typedef struct{
  uint8_t  buffer[28];
}LIBLTE_X2AP_EUTRANCELLIDENTIFIER_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_eutrancellidentifier(
  LIBLTE_X2AP_EUTRANCELLIDENTIFIER_STRUCT                               *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_eutrancellidentifier(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_EUTRANCELLIDENTIFIER_STRUCT                               *ie);

/*******************************************************************************
/* ProtocolIE Fourframes STATIC BIT STRING
********************************************************************************/
#define LIBLTE_X2AP_FOURFRAMES_BIT_STRING_LEN 24
typedef struct{
  uint8_t  buffer[24];
}LIBLTE_X2AP_FOURFRAMES_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_fourframes(
  LIBLTE_X2AP_FOURFRAMES_STRUCT                         *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_fourframes(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_FOURFRAMES_STRUCT                         *ie);

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
      liblte_log_print("IntegrityProtectionAlgorithms error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("IntegrityProtectionAlgorithms error: S1AP ASN extensions not currently supported\n");
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
#define LIBLTE_X2AP_KEY_ENODEB_STAR_BIT_STRING_LEN 256
typedef struct{
  uint8_t  buffer[256];
}LIBLTE_X2AP_KEY_ENODEB_STAR_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_key_enodeb_star(
  LIBLTE_X2AP_KEY_ENODEB_STAR_STRUCT                         *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_key_enodeb_star(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_KEY_ENODEB_STAR_STRUCT                          *ie);


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
#define LIBLTE_X2AP_ONEFRAME_BIT_STRING_LEN 6
typedef struct{
  uint8_t  buffer[6];
}LIBLTE_X2AP_ONEFRAME_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_oneframe(
  LIBLTE_X2AP_ONEFRAME_STRUCT                         *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_oneframe(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ONEFRAME_STRUCT                         *ie);


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
#define LIBLTE_X2AP_REPORTCHARATERISTICS_BIT_STRING_LEN 32
typedef struct{
  uint8_t  buffer[32];
}LIBLTE_X2AP_REPORTCHARACTERISTICS_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_reportcharacteristics(
  LIBLTE_X2AP_REPORTCHARACTERISTICS_STRUCT                     *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_reportcharacteristics(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_REPORTCHARACTERISTICS_STRUCT                     *ie);

/*******************************************************************************
/* ProtocolIE ShortMAC_I STATIC BIT STRING
********************************************************************************/
#define LIBLTE_X2AP_SHORTMAC_I_BIT_STRING_LEN 16
typedef struct{
  uint8_t  buffer[16];
}LIBLTE_X2AP_SHORTMAC_I_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_shortmac_i(
  LIBLTE_X2AP_SHORTMAC_I_STRUCT                       *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_shortmac_i(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_SHORTMAC_I_STRUCT                       *ie);

/*******************************************************************************
/* ProtocolIE TraceCollectionEntityIPAddress DYNAMIC BIT STRING
********************************************************************************/
// lb:1, ub:160
typedef struct{
  bool     ext;
  uint32_t n_bits;
  uint8_t  buffer[160];
}LIBLTE_X2AP_TRACECOLLECTIONENTITYIPADDRESS_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_tracecollectionentityipaddress(
  LIBLTE_X2AP_TRACECOLLECTIONENTITYIPADDRESS_STRUCT                     *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_tracecollectionentityipaddress(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TRACECOLLECTIONENTITYIPADDRESS_STRUCT                     *ie);


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
      liblte_log_print("TransportLayerAddress error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("TransportLayerAddress error: S1AP ASN extensions not currently supported\n");
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
// lb:1, ub:120
typedef struct{
  bool     ext;
  uint32_t n_bits;
  uint8_t  buffer[120];
}LIBLTE_X2AP_UL_HIGHINTERFERENCEINDICATION_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ul_highinterferenceindication(
  LIBLTE_X2AP_UL_HIGHINTERFERENCEINDICATION_STRUCT                               *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ul_highinterferenceindication(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UL_HIGHINTERFERENCEINDICATION_STRUCT                               *ie);


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
#define LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_OCTET_STRING_LEN 2
typedef struct{
  uint8_t  buffer[2];
}LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_mbms_service_area_identity(
  LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_STRUCT                                  *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_mbms_service_area_identity(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_MBMS_SERVICE_AREA_IDENTITY_STRUCT                                  *ie);

/*******************************************************************************
/* ProtocolIE PLMNidentity STATIC OCTET STRING
********************************************************************************/
LIBLTE_ERROR_ENUM liblte_x2ap_pack_plmnidentity(
  LIBLTE_X2AP_PLMNIDENTITY_STRUCT                                    *ie,
  uint8_t                                                           **ptr)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - PLMNidentity
    if(LIBLTE_X2AP_PLMNIDENTITY_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up_zero(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_PLMNIDENTITY_OCTET_STRING_LEN;i++) {
      liblte_value_2_bits(ie->buffer[i], ptr, 8);
    }
    err = LIBLTE_SUCCESS;
  }
  return err;
}

LIBLTE_ERROR_ENUM liblte_x2ap_unpack_plmnidentity(
  uint8_t                                                           **ptr,
  LIBLTE_X2AP_PLMNIDENTITY_STRUCT                                    *ie)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;

  if(ie  != NULL &&
     ptr != NULL)
  {
    // Static octet string - PLMNidentity
    if(LIBLTE_X2AP_PLMNIDENTITY_OCTET_STRING_LEN > 2) { // X.691 Sec.16
      liblte_align_up(ptr, 8);
    }
    // Octets
    uint32_t i;
    for(i=0;i<LIBLTE_X2AP_PLMNIDENTITY_OCTET_STRING_LEN;i++) {
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
// lb:0, ub:16318
typedef struct{
  uint32_t n_octets;
  uint8_t  buffer[16318];
}LIBLTE_X2AP_TARGETCELLINUTRAN_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_targetcellinutran(
  LIBLTE_X2AP_TARGETCELLINUTRAN_STRUCT                         *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_targetcellinutran(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TARGETCELLINUTRAN_STRUCT                         *ie);

/*******************************************************************************
/* ProtocolIE TargeteNBtoSource_eNBTransparentContainer DYNAMIC OCTET STRING
********************************************************************************/
// lb:0, ub:16318
typedef struct{
  uint32_t n_octets;
  uint8_t  buffer[16318];
}LIBLTE_X2AP_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_targetenbtosource_enbtransparentcontainer(
  LIBLTE_X2AP_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER_STRUCT                         *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_targetenbtosource_enbtransparentcontainer(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER_STRUCT                         *ie);

/*******************************************************************************
/* ProtocolIE UL_RLF_Report_Container DYNAMIC OCTET STRING
********************************************************************************/
// lb:0, ub:16318
typedef struct{
  uint32_t n_octets;
  uint8_t  buffer[16318];
}LIBLTE_X2AP_UE_RLF_REPORT_CONTAINER_STRUCT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_ue_rlf_report_container(
  LIBLTE_X2AP_UE_RLF_REPORT_CONTAINER_STRUCT                         *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_ue_rlf_report_container(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_UE_RLF_REPORT_CONTAINER_STRUCT                         *ie);

/* ENUMERATED */

/*******************************************************************************
/* ProtocolIE AdditionalSpecialSubframePatterns ENUMERATED
********************************************************************************/
typedef struct{
  bool                                                         ext;
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM e;
}LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM_EXT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_additionalspecialsubframepatterns(
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM_EXT                               *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_additionalspecialsubframepatterns(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_ADDITIONALSPECIALSUBFRAMEPATTERNS_ENUM_EXT                               *ie);

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
      liblte_log_print("CauseMisc error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseMisc error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseProtocol error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseProtocol error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseRadioNetwork error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseRadioNetwork error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseTransport error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("CauseTransport error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("Cell_Size error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("Cell_Size error: S1AP ASN extensions not currently supported\n");
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
typedef enum{
  LIBLTE_X2AP_CYCLICPREFIXDL_NORMAL,
  LIBLTE_X2AP_CYCLICPREFIXDL_EXTENDED,
  LIBLTE_X2AP_CYCLICPREFIXDL_N_ITEMS,
}LIBLTE_X2AP_CYCLICPREFIXDL_ENUM;
static const char liblte_x2ap_cyclicprefixdl_text[LIBLTE_X2AP_CYCLICPREFIXDL_N_ITEMS][80] = {
  "normal",
  "extended",
};

typedef struct{
  bool                                                         ext;
  LIBLTE_X2AP_CYCLICPREFIXDL_ENUM e;
}LIBLTE_X2AP_CYCLICPREFIXDL_ENUM_EXT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cyclicprefixdl(
  LIBLTE_X2AP_CYCLICPREFIXDL_ENUM_EXT                                    *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cyclicprefixdl(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CYCLICPREFIXDL_ENUM_EXT                                   *ie);

/*******************************************************************************
/* ProtocolIE CyclicPrefixUL ENUMERATED
********************************************************************************/
typedef enum{
  LIBLTE_X2AP_CYCLICPREFIXUL_NORMAL,
  LIBLTE_X2AP_CYCLICPREFIXUL_EXTENDED,
  LIBLTE_X2AP_CYCLICPREFIXUL_N_ITEMS,
}LIBLTE_X2AP_CYCLICPREFIXUL_ENUM;
static const char liblte_x2ap_cyclicprefixul_text[LIBLTE_X2AP_CYCLICPREFIXUL_N_ITEMS][80] = {
  "normal",
  "extended",
};

typedef struct{
  bool                                                         ext;
  LIBLTE_X2AP_CYCLICPREFIXUL_ENUM e;
}LIBLTE_X2AP_CYCLICPREFIXUL_ENUM_EXT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_cyclicprefixul(
  LIBLTE_X2AP_CYCLICPREFIXUL_ENUM_EXT                                    *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_cyclicprefixul(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_CYCLICPREFIXUL_ENUM_EXT                                   *ie);

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
      liblte_log_print("DL_Forwarding error: S1AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_ENCODE_FAIL;
    }

    // Enum
    liblte_value_2_bits(ie->e, ptr, 0);
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
      liblte_log_print("DL_Forwarding error: S1AP ASN extensions not currently supported\n");
      return LIBLTE_ERROR_DECODE_FAIL;
    }

    // Enum
    ie->e = (LIBLTE_X2AP_DL_FORWARDING_ENUM)liblte_bits_2_value(ptr, 0);
    liblte_align_up(ptr, 8);
    err = LIBLTE_SUCCESS;
  }
  return err;
}

/*******************************************************************************
/* ProtocolIE DeactivationIndication ENUMERATED
********************************************************************************/
typedef enum{
  LIBLTE_X2AP_DEACTIVATIONINDICATION_DEACTIVATED,
  LIBLTE_X2AP_DEACTIVATIONINDICATION_N_ITEMS,
}LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM;
static const char liblte_x2ap_deactivationindication_text[LIBLTE_X2AP_DEACTIVATIONINDICATION_N_ITEMS][80] = {
  "deactivated",
};

typedef struct{
  bool                                                         ext;
  LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM e;
}LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM_EXT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_deactivationindication(
  LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM_EXT            *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_deactivationindication(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_DEACTIVATIONINDICATION_ENUM_EXT            *ie);

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
      liblte_log_print("EventType error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("EventType error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("ForbiddenInterRATs error: S1AP ASN extensions not currently supported\n");
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
      liblte_log_print("ForbiddenInterRATs error: S1AP ASN extensions not currently supported\n");
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
typedef enum{
  LIBLTE_X2AP_HANDOVERREPORTTYPE_HOTOOEARLY,
  LIBLTE_X2AP_HANDOVERREPORTTYPE_HOTOWRONGCELL,
  LIBLTE_X2AP_HANDOVERREPORTTYPE_INTERRATPINGPONG,
  LIBLTE_X2AP_HANDOVERREPORTTYPE_N_ITEMS,
}LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM;
static const char liblte_x2ap_handoverreporttype_text[LIBLTE_X2AP_HANDOVERREPORTTYPE_N_ITEMS][80] = {
  "hoTooEarly",
  "hoToWrongCell",
  "interRATpingpong",
};

typedef struct{
  bool                                                         ext;
  LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM e;
}LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM_EXT;

LIBLTE_ERROR_ENUM liblte_x2ap_pack_handoverreporttype(
  LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM_EXT                            *ie,
  uint8_t                                                     **ptr);
LIBLTE_ERROR_ENUM liblte_x2ap_unpack_handoverreporttype(
  uint8_t                                                     **ptr,
  LIBLTE_X2AP_HANDOVERREPORTTYPE_ENUM_EXT                            *ie);



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
      } else      if(LIBLTE_X2AP_IE_ID_E_RABS_ADMITTED_LIST == ie_id) {
        /*if(liblte_x2ap_unpack_e_rabs_admitted_list(ptr, &msg->E_RABs_Admitted_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_E_RABS_NOTADMITTED_LIST == ie_id) {
        /*if(liblte_x2ap_unpack_e_rab_list(ptr, &msg->E_RABs_NotAdmitted_List) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->E_RABs_NotAdmitted_List_present = true;
      } else      if(LIBLTE_X2AP_IE_ID_TARGETENBTOSOURCE_ENBTRANSPARENTCONTAINER == ie_id) {
        /*if(liblte_x2ap_unpack_targetenbtosource_enbtransparentcontainer(ptr, &msg->TargeteNBtoSource_eNBTransparentContainer) != LIBLTE_SUCCESS) {
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

    // ProtocolIE - TimeToWait
    if(msg->TimeToWait_present) {
      tmp_msg.reset();
      tmp_ptr = tmp_msg.msg;
      /*if(liblte_x2ap_pack_timetowait(&msg->TimeToWait, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
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
      /*if(liblte_x2ap_pack_gugroupidlist(&msg->GUGroupIDList, &tmp_ptr) != LIBLTE_SUCCESS) {
        return LIBLTE_ERROR_ENCODE_FAIL;
      }*/
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
        /*if(liblte_x2ap_unpack_cause(ptr, &msg->Cause) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
      } else      if(LIBLTE_X2AP_IE_ID_TIMETOWAIT == ie_id) {
        /*if(liblte_x2ap_unpack_timetowait(ptr, &msg->TimeToWait) != LIBLTE_SUCCESS) {
          return LIBLTE_ERROR_DECODE_FAIL;
        }*/
        liblte_align_up(ptr, 8);
        msg->TimeToWait_present = true;
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
