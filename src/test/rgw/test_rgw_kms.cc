// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <gtest/gtest.h>
#include "common/ceph_context.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_kms.h"

TEST(TestSSEKMS, invalid_backend)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  cct->_conf.set_val("rgw_crypt_s3_kms_backend", "invalid");

  std::string key_id, key_selector, actual_key;
  ASSERT_EQ(
      get_actual_key_from_kms(cct, key_id, key_selector, actual_key),
      -EINVAL
  );
}

TEST(TestSSEKMS, invalid_vault_auth)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  cct->_conf.set_val("rgw_crypt_s3_kms_backend", "vault");
  cct->_conf.set_val("rgw_crypt_s3_kms_vault_auth", "invalid");

  std::string key_id, key_selector, actual_key;
  ASSERT_EQ(
      get_actual_key_from_kms(cct, key_id, key_selector, actual_key),
      -EINVAL
  );
}

TEST(TestSSEKMS, vault_token_file_unset)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  cct->_conf.set_val("rgw_crypt_s3_kms_backend", "vault");
  cct->_conf.set_val("rgw_crypt_s3_kms_vault_auth", "token");

  std::string key_id, key_selector, actual_key;
  ASSERT_EQ(
      get_actual_key_from_kms(cct, key_id, key_selector, actual_key),
      -EINVAL
  );
}

TEST(TestSSEKMS, non_existent_vault_token_file)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  cct->_conf.set_val("rgw_crypt_s3_kms_backend", "vault");
  cct->_conf.set_val("rgw_crypt_s3_kms_vault_auth", "token");
  cct->_conf.set_val("rgw_crypt_s3_kms_vault_token_file", "non_existent_file");

  std::string key_id, key_selector, actual_key;
  ASSERT_EQ(
      get_actual_key_from_kms(cct, key_id, key_selector, actual_key),
      -ENOENT
  );
}
