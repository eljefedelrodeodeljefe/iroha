/**
 * Copyright Soramitsu Co., Ltd. 2017 All Rights Reserved.
 * http://soramitsu.co.jp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IROHA_COMMANDS_VALIDATOR_HPP
#define IROHA_COMMANDS_VALIDATOR_HPP

#include <boost/format.hpp>
#include <boost/variant/static_visitor.hpp>
#include <regex>
#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/transaction.hpp"
#include "utils/polymorphic_wrapper.hpp"
#include "validators/answer.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Class that validates commands from transaction
     */
    class CommandsValidator {
     private:
      /**
       * Visitor used by commands validator to validate fields from tx commands
       */
      class CommandsValidatorVisitor
          : public boost::static_visitor<ReasonsGroupType> {
       public:
        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::AddAssetQuantity> &aaq)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("AddAssetQuantity");

          validateAccountId(reason, aaq->accountId());
          validateAssetId(reason, aaq->assetId());
          validateAmount(reason, aaq->amount());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::AddPeer> &ap) const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("AddPeer");

          validatePubkey(reason, ap->peerKey());
          validatePeerAddress(reason, ap->peerAddress());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::AddSignatory> &as)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("AddSignatory");

          validateAccountId(reason, as->accountId());
          validatePubkey(reason, as->pubkey());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::AppendRole> &ar) const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("AppendRole");

          validateAccountId(reason, ar->accountId());
          validateRoleId(reason, ar->roleName());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::CreateAccount> &ca)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("CreateAccount");

          validatePubkey(reason, ca->pubkey());
          validateAccountName(reason, ca->accountName());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::CreateAsset> &ca)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("CreateAsset");

          validateAssetName(reason, ca->assetName());
          validateDomainId(reason, ca->domainId());
          validatePrecision(reason, ca->precision());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::CreateDomain> &cd)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("CreateDomain");

          validateDomainId(reason, cd->domainId());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::CreateRole> &cr) const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("CreateRole");

          validateRoleId(reason, cr->roleName());
          validatePermissions(reason, cr->rolePermissions());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::DetachRole> &dr) const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("DetachRole");

          validateAccountId(reason, dr->accountId());
          validateRoleId(reason, dr->roleName());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::GrantPermission> &gp)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("GrantPermission");

          validateAccountId(reason, gp->accountId());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::RemoveSignatory> &rs)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("RemoveSignatory");

          validateAccountId(reason, rs->accountId());
          validatePubkey(reason, rs->pubkey());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::RevokePermission> &rp)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("RevokePermission");

          validateAccountId(reason, rp->accountId());
          validatePermission(reason, rp->permissionName());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::SetAccountDetail> &sad)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("SetAccountDetail");

          validateAccountId(reason, sad->accountId());
          validateAccountDetailKey(reason, sad->key());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::SetQuorum> &sq) const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("SetQuorum");

          validateAccountId(reason, sq->accountId());
          validateQuorum(reason, sq->newQuorum());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::SubtractAssetQuantity>
                &saq) const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("SubtractAssetQuantity");

          validateAccountId(reason, saq->accountId());
          validateAssetId(reason, saq->assetId());
          validateAmount(reason, saq->amount());

          command_counter++;
          return reason;
        }

        ReasonsGroupType operator()(
            const detail::PolymorphicWrapper<interface::TransferAsset> &ta)
            const {
          ReasonsGroupType reason;
          reason.first = generate_command_string("TransferAsset");

          validateAccountId(reason, ta->srcAccountId());
          validateAccountId(reason, ta->destAccountId());
          validateAssetId(reason, ta->assetId());
          validateAmount(reason, ta->amount());

          command_counter++;
          return reason;
        }

       private:
        mutable int command_counter{0};

        // command string consists of command name
        // and its number in the transaction
        std::string generate_command_string(const std::string &command) const {
          return (boost::format("%s %d") % command % command_counter).str();
        }

        std::string generate_error(const std::string &message,
                                   const std::string &value) const {
          return (boost::format("%s: \"%s\"") % message % value).str();
        }

        void validateAccountId(
            ReasonsGroupType &reason,
            const interface::types::AccountIdType &account_id) const {
          std::regex e(R"([a-z]{1,9}\@[a-z]{1,9})");
          if (not std::regex_match(account_id, e)) {
            auto error_message =
                generate_error("Wrongly formed account_id",
                               static_cast<std::string>(account_id));
            reason.second.push_back(error_message);
          }
        }

        void validateAssetId(
            ReasonsGroupType &reason,
            const interface::types::AssetIdType &asset_id) const {
          std::regex e(R"([a-z]{1,9}\#[a-z]{1,9})");
          if (not std::regex_match(asset_id, e)) {
            auto error_message = generate_error(
                "Wrongly formed asset_id", static_cast<std::string>(asset_id));
            reason.second.push_back(error_message);
          }
        }

        void validateAmount(ReasonsGroupType &reason,
                            const interface::Amount &amount) const {
          // put here any validations
        }

        void validatePubkey(ReasonsGroupType &reason,
                            const interface::types::PubkeyType &pubkey) const {
          if (pubkey.blob().size() != 32) {
            auto error_message =
                generate_error("Public key has wrong size",
                               std::to_string(pubkey.blob().size()));
            reason.second.push_back(error_message);
          }
        }

        void validatePeerAddress(
            ReasonsGroupType &reason,
            const interface::AddPeer::AddressType &address) const {
          if (address != "localhost") {
            std::regex ipRegex(
                "((([0-1]?\\d\\d?)|((2[0-4]\\d)|(25[0-5]))).){3}(([0-1]?\\d\\d?"
                ")|((2[0-4]"
                "\\d)|(25[0-5])))");
            if (not std::regex_match(address, ipRegex)) {
              auto error_message =
                  generate_error("Wrongly formed PeerAddress",
                                 static_cast<std::string>(address));
              reason.second.push_back(error_message);
            }
          }
        }

        void validateRoleId(ReasonsGroupType &reason,
                            const interface::types::RoleIdType &role_id) const {
          std::regex e(R"([a-z]{1,9})");
          if (not std::regex_match(role_id, e)) {
            auto error_message = generate_error(
                "Wrongly formed role_id", static_cast<std::string>(role_id));
            reason.second.push_back(error_message);
          }
        }

        void validateAccountName(
            ReasonsGroupType &reason,
            const interface::types::AccountNameType &account_name) const {
          std::regex e(R"([a-z]{1,9})");
          if (not std::regex_match(account_name, e)) {
            auto error_message =
                generate_error("Wrongly formed account_name",
                               static_cast<std::string>(account_name));
            reason.second.push_back(error_message);
          }
        }

        void validateDomainId(
            ReasonsGroupType &reason,
            const interface::types::DomainIdType &domain_id) const {
          std::regex e(R"([a-z]{1,9})");
          if (not std::regex_match(domain_id, e)) {
            auto error_message =
                generate_error("Wrongly formed domain_id",
                               static_cast<std::string>(domain_id));
            reason.second.push_back(error_message);
          }
        }

        void validateAssetName(
            ReasonsGroupType &reason,
            const interface::types::AssetNameType &asset_name) const {
          std::regex e(R"([a-z]{1,9})");
          if (not std::regex_match(asset_name, e)) {
            auto error_message =
                generate_error("Wrongly formed asset_name",
                               static_cast<std::string>(asset_name));
            reason.second.push_back(error_message);
          }
        }

        void validateAccountDetailKey(
            ReasonsGroupType &reason,
            const interface::SetAccountDetail::AccountDetailKeyType &key)
            const {
          std::regex e(R"([A-Za-z0-9_]{1,})");
          if (not std::regex_match(key, e)) {
            auto error_message = generate_error("Wrongly formed key",
                                                static_cast<std::string>(key));
            reason.second.push_back(error_message);
          }
        }

        void validatePrecision(
            ReasonsGroupType &reason,
            const interface::types::PrecisionType &precision) const {
          // define precision constraints
        }

        void validatePermission(
            ReasonsGroupType &reason,
            const interface::types::PermissionNameType &permission_name) const {
          // define permission constraints
        }

        void validatePermissions(
            ReasonsGroupType &reason,
            const interface::CreateRole::PermissionsType &permissions) const {
          if (permissions.empty()) {
            reason.second.push_back(
                "Permission set should contain at least one permission");
          }
        }

        void validateQuorum(ReasonsGroupType &reason,
                            const interface::types::QuorumType &quorum) const {
          // define quorum constraints
        }
      };

     public:
      /**
       * Applies command validation on given tx
       * @param tx
       * @return Answer containing found error if any
       */
      Answer validate(
          detail::PolymorphicWrapper<interface::Transaction> tx) const {
        Answer answer;
        std::string tx_reason_name = "Transaction";
        ReasonsGroupType tx_reason(tx_reason_name, GroupedReasons());

        validateAmountOfCommands(tx_reason, tx->commands().size());
        validateCreatorAccountId(tx_reason, tx->creatorAccountId());
        validateCreatedTime(tx_reason, tx->createdTime());
        if (not tx_reason.second.empty()) {
          answer.addReason(std::move(tx_reason));
        }

        CommandsValidatorVisitor validator;
        for (auto &command : tx->commands()) {
          auto reason = boost::apply_visitor(validator, command->get());
          if (not reason.second.empty()) {
            answer.addReason(std::move(reason));
          }
        }

        return answer;
      }

     private:
      void validateAmountOfCommands(ReasonsGroupType &reason,
                                    size_t size) const {
        if (size == 0) {
          reason.second.push_back(
              "Transaction should contain at least one command");
        }
      }

      void validateCreatorAccountId(
          ReasonsGroupType &reason,
          const interface::types::AccountIdType &account_id) const {
        std::regex e(R"([a-z]{1,9}\@[a-z]{1,9})");
        if (not std::regex_match(account_id, e)) {
          reason.second.push_back(
              (boost::format("Wrongly formed creator_account_id: \"%s\"")
               % static_cast<std::string>(account_id))
                  .str());
        }
      }

      void validateCreatedTime(
          ReasonsGroupType &reason,
          const interface::types::TimestampType &timestamp) const {
        iroha::ts64_t now = iroha::time::now();
        // TODO 06/08/17 Muratov: make future gap for passing timestamp, like
        // with old timestamps IR-511 #goodfirstissue
        if (now < timestamp) {
          auto message =
              boost::format(
                  "timestamp broken: send from future (%llu, now %llu)")
              % timestamp % now;
          reason.second.push_back(message.str());
        }

        if (now - timestamp > MAX_DELAY) {
          auto message =
              boost::format("timestamp broken: too old (%llu, now %llu)")
              % timestamp % now;
          reason.second.push_back(message.str());
        }
      }

      // max-delay between tx creation and validation
      static constexpr auto MAX_DELAY =
          std::chrono::hours(24) / std::chrono::milliseconds(1);
      Answer answer_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_COMMANDS_VALIDATOR_HPP
