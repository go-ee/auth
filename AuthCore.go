package auth

import (
	"github.com/go-ee/utils/crypt"
)

func (o *AuthEventhorizonInitializer) ActivatePasswordEncryption() {
	o.AccountAggregateInitializer.AddCreatePreparer(
		func(cmd *CreateAccount, entity *Account) (err error) {
			cmd.Password, err = crypt.Hash(cmd.Password)
			return
		})

	o.AccountAggregateInitializer.AddUpdatePreparer(
		func(cmd *UpdateAccount, entity *Account) (err error) {
			if len(cmd.Password) > 0 {
				cmd.Password, err = crypt.Hash(cmd.Password)
			}
			return
		})
}
