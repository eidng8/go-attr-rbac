// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

// PersonalTokenCreate is the builder for creating a PersonalToken entity.
type PersonalTokenCreate struct {
	config
	mutation *PersonalTokenMutation
	hooks    []Hook
}

// SetUserID sets the "user_id" field.
func (ptc *PersonalTokenCreate) SetUserID(u uint64) *PersonalTokenCreate {
	ptc.mutation.SetUserID(u)
	return ptc
}

// SetDescription sets the "description" field.
func (ptc *PersonalTokenCreate) SetDescription(s string) *PersonalTokenCreate {
	ptc.mutation.SetDescription(s)
	return ptc
}

// SetToken sets the "token" field.
func (ptc *PersonalTokenCreate) SetToken(b []byte) *PersonalTokenCreate {
	ptc.mutation.SetToken(b)
	return ptc
}

// SetCreatedAt sets the "created_at" field.
func (ptc *PersonalTokenCreate) SetCreatedAt(t time.Time) *PersonalTokenCreate {
	ptc.mutation.SetCreatedAt(t)
	return ptc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (ptc *PersonalTokenCreate) SetNillableCreatedAt(t *time.Time) *PersonalTokenCreate {
	if t != nil {
		ptc.SetCreatedAt(*t)
	}
	return ptc
}

// SetID sets the "id" field.
func (ptc *PersonalTokenCreate) SetID(u uint64) *PersonalTokenCreate {
	ptc.mutation.SetID(u)
	return ptc
}

// SetOwnerID sets the "owner" edge to the User entity by ID.
func (ptc *PersonalTokenCreate) SetOwnerID(id uint64) *PersonalTokenCreate {
	ptc.mutation.SetOwnerID(id)
	return ptc
}

// SetNillableOwnerID sets the "owner" edge to the User entity by ID if the given value is not nil.
func (ptc *PersonalTokenCreate) SetNillableOwnerID(id *uint64) *PersonalTokenCreate {
	if id != nil {
		ptc = ptc.SetOwnerID(*id)
	}
	return ptc
}

// SetOwner sets the "owner" edge to the User entity.
func (ptc *PersonalTokenCreate) SetOwner(u *User) *PersonalTokenCreate {
	return ptc.SetOwnerID(u.ID)
}

// Mutation returns the PersonalTokenMutation object of the builder.
func (ptc *PersonalTokenCreate) Mutation() *PersonalTokenMutation {
	return ptc.mutation
}

// Save creates the PersonalToken in the database.
func (ptc *PersonalTokenCreate) Save(ctx context.Context) (*PersonalToken, error) {
	ptc.defaults()
	return withHooks(ctx, ptc.sqlSave, ptc.mutation, ptc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ptc *PersonalTokenCreate) SaveX(ctx context.Context) *PersonalToken {
	v, err := ptc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ptc *PersonalTokenCreate) Exec(ctx context.Context) error {
	_, err := ptc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ptc *PersonalTokenCreate) ExecX(ctx context.Context) {
	if err := ptc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ptc *PersonalTokenCreate) defaults() {
	if _, ok := ptc.mutation.CreatedAt(); !ok {
		v := personaltoken.DefaultCreatedAt()
		ptc.mutation.SetCreatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ptc *PersonalTokenCreate) check() error {
	if _, ok := ptc.mutation.UserID(); !ok {
		return &ValidationError{Name: "user_id", err: errors.New(`ent: missing required field "PersonalToken.user_id"`)}
	}
	if _, ok := ptc.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "PersonalToken.description"`)}
	}
	if v, ok := ptc.mutation.Description(); ok {
		if err := personaltoken.DescriptionValidator(v); err != nil {
			return &ValidationError{Name: "description", err: fmt.Errorf(`ent: validator failed for field "PersonalToken.description": %w`, err)}
		}
	}
	if _, ok := ptc.mutation.Token(); !ok {
		return &ValidationError{Name: "token", err: errors.New(`ent: missing required field "PersonalToken.token"`)}
	}
	return nil
}

func (ptc *PersonalTokenCreate) sqlSave(ctx context.Context) (*PersonalToken, error) {
	if err := ptc.check(); err != nil {
		return nil, err
	}
	_node, _spec := ptc.createSpec()
	if err := sqlgraph.CreateNode(ctx, ptc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != _node.ID {
		id := _spec.ID.Value.(int64)
		_node.ID = uint64(id)
	}
	ptc.mutation.id = &_node.ID
	ptc.mutation.done = true
	return _node, nil
}

func (ptc *PersonalTokenCreate) createSpec() (*PersonalToken, *sqlgraph.CreateSpec) {
	var (
		_node = &PersonalToken{config: ptc.config}
		_spec = sqlgraph.NewCreateSpec(personaltoken.Table, sqlgraph.NewFieldSpec(personaltoken.FieldID, field.TypeUint64))
	)
	if id, ok := ptc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := ptc.mutation.UserID(); ok {
		_spec.SetField(personaltoken.FieldUserID, field.TypeUint64, value)
		_node.UserID = value
	}
	if value, ok := ptc.mutation.Description(); ok {
		_spec.SetField(personaltoken.FieldDescription, field.TypeString, value)
		_node.Description = value
	}
	if value, ok := ptc.mutation.Token(); ok {
		_spec.SetField(personaltoken.FieldToken, field.TypeBytes, value)
		_node.Token = value
	}
	if value, ok := ptc.mutation.CreatedAt(); ok {
		_spec.SetField(personaltoken.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = &value
	}
	if nodes := ptc.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   personaltoken.OwnerTable,
			Columns: []string{personaltoken.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUint64),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_personal_tokens = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// PersonalTokenCreateBulk is the builder for creating many PersonalToken entities in bulk.
type PersonalTokenCreateBulk struct {
	config
	err      error
	builders []*PersonalTokenCreate
}

// Save creates the PersonalToken entities in the database.
func (ptcb *PersonalTokenCreateBulk) Save(ctx context.Context) ([]*PersonalToken, error) {
	if ptcb.err != nil {
		return nil, ptcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(ptcb.builders))
	nodes := make([]*PersonalToken, len(ptcb.builders))
	mutators := make([]Mutator, len(ptcb.builders))
	for i := range ptcb.builders {
		func(i int, root context.Context) {
			builder := ptcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*PersonalTokenMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, ptcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ptcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil && nodes[i].ID == 0 {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = uint64(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, ptcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ptcb *PersonalTokenCreateBulk) SaveX(ctx context.Context) []*PersonalToken {
	v, err := ptcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ptcb *PersonalTokenCreateBulk) Exec(ctx context.Context) error {
	_, err := ptcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ptcb *PersonalTokenCreateBulk) ExecX(ctx context.Context) {
	if err := ptcb.Exec(ctx); err != nil {
		panic(err)
	}
}