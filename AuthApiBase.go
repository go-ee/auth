package auth

import (
    "github.com/google/uuid"
)
        
type Account struct {
    Name *PersonName `json:"name" eh:"optional"`
    Username string `json:"username" eh:"optional"`
    Password string `json:"password" eh:"optional"`
    Email string `json:"email" eh:"optional"`
    Roles []string `json:"roles" eh:"optional"`
    Disabled bool `json:"disabled" eh:"optional"`
    Id uuid.UUID `json:"id" eh:"optional"`
}

func NewAccount() (ret *Account) {
    ret = &Account{}
    return
}

func (o *Account) AddToRoles(item string) string {
    o.Roles = append(o.Roles, item)
    return item
}
func (o *Account) EntityID() uuid.UUID { return o.Id }





type UserCredentials struct {
    Username string `json:"username" eh:"optional"`
    Password string `json:"password" eh:"optional"`
}

func NewUserCredentials() (ret *UserCredentials) {
    ret = &UserCredentials{}
    return
}




type PersonName struct {
    First string `json:"first" eh:"optional"`
    Last string `json:"last" eh:"optional"`
}

func NewPersonName() (ret *PersonName) {
    ret = &PersonName{}
    return
}





