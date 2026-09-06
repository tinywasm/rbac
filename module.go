package rbac

import (
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/user"
)

// Service owns role, permission, and subject-assignment persistence,
// scoped by project — every table carries project_id, so one Service over
// one database serves every consuming project (see ARCHITECTURE.md).
type Service struct {
	db     *orm.DB
	ucache *userCache
}

// New creates an authorization service over the injected database.
func New(db *orm.DB) (*Service, error) {
	return &Service{db: db, ucache: newUserCache()}, nil
}

// Can reports whether subjectID has a grant for resource/action within projectID.
func (s *Service) Can(projectID, subjectID string, resource model.Resource, action model.Action) bool {
	ok, err := s.HasPermission(projectID, subjectID, resource, action)
	return err == nil && ok
}

// CanSubject is the typed alias for Can that accepts the stable user.SubjectID.
func (s *Service) CanSubject(projectID string, id user.SubjectID, resource model.Resource, action model.Action) bool {
	return s.Can(projectID, string(id), resource, action)
}
