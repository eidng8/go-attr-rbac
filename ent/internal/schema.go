// Code generated by ent, DO NOT EDIT.

//go:build tools
// +build tools

// Package internal holds a loadable version of the latest schema.
package internal

const Schema = "{\"Schema\":\"github.com/eidng8/go-attr-rbac/ent/schema\",\"Package\":\"github.com/eidng8/go-attr-rbac/ent\",\"Schemas\":[{\"name\":\"AccessToken\",\"config\":{\"Table\":\"\"},\"edges\":[{\"name\":\"owner\",\"type\":\"User\",\"ref_name\":\"access_tokens\",\"unique\":true,\"inverse\":true,\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":1},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}}],\"fields\":[{\"name\":\"id\",\"type\":{\"Type\":18,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"position\":{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint64\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"user_id\",\"type\":{\"Type\":18,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"immutable\":true,\"position\":{\"Index\":1,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint64\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"access_token\",\"type\":{\"Type\":5,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":true,\"RType\":null},\"unique\":true,\"immutable\":true,\"position\":{\"Index\":2,\"MixedIn\":false,\"MixinIndex\":0},\"sensitive\":true,\"schema_type\":{\"mysql\":\"binary(16)\",\"postgres\":\"binary(16)\",\"sqlite3\":\"blob\"},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":true,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"refresh_token\",\"type\":{\"Type\":5,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":true,\"RType\":null},\"unique\":true,\"immutable\":true,\"position\":{\"Index\":3,\"MixedIn\":false,\"MixinIndex\":0},\"sensitive\":true,\"schema_type\":{\"mysql\":\"binary(16)\",\"postgres\":\"binary(16)\",\"sqlite3\":\"blob\"},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":true,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"created_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"default\":true,\"default_kind\":19,\"immutable\":true,\"position\":{\"Index\":4,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"date-time\",\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}}],\"annotations\":{\"Comment\":{\"Text\":\"Stores revoked access tokens\"},\"Edges\":{\"StructTag\":\"json:\\\"-\\\"\"},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"Permission\",\"config\":{\"Table\":\"\"},\"edges\":[{\"name\":\"roles\",\"type\":\"Role\",\"ref_name\":\"permissions\",\"inverse\":true,\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":1},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}}],\"fields\":[{\"name\":\"id\",\"type\":{\"Type\":16,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"position\":{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint32\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"name\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"unique\":true,\"validators\":1,\"position\":{\"Index\":1,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"maxLength\":255,\"minLength\":1,\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"description\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"optional\":true,\"position\":{\"Index\":2,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"maxLength\":255,\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"created_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"default\":true,\"default_kind\":19,\"immutable\":true,\"position\":{\"Index\":3,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":true,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"updated_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"update_default\":true,\"immutable\":true,\"position\":{\"Index\":4,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":true,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}}],\"annotations\":{\"Edges\":{\"StructTag\":\"json:\\\"-\\\"\"},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"PersonalToken\",\"config\":{\"Table\":\"\"},\"edges\":[{\"name\":\"owner\",\"type\":\"User\",\"ref_name\":\"personal_tokens\",\"unique\":true,\"inverse\":true,\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":1},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}}],\"fields\":[{\"name\":\"id\",\"type\":{\"Type\":18,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"position\":{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint64\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"user_id\",\"type\":{\"Type\":18,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"immutable\":true,\"position\":{\"Index\":1,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint64\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"description\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"validators\":1,\"position\":{\"Index\":2,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint64\",\"maxLength\":255,\"minLength\":2,\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"token\",\"type\":{\"Type\":5,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":true,\"RType\":null},\"unique\":true,\"immutable\":true,\"position\":{\"Index\":3,\"MixedIn\":false,\"MixinIndex\":0},\"sensitive\":true,\"schema_type\":{\"mysql\":\"binary(16)\",\"postgres\":\"binary(16)\",\"sqlite3\":\"blob\"},\"annotations\":{\"Comment\":{\"Text\":\"token JTI\"},\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":true,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"created_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"default\":true,\"default_kind\":19,\"immutable\":true,\"position\":{\"Index\":4,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"date-time\",\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}}],\"annotations\":{\"Comment\":{\"Text\":\"Stores issued long-lived tokens\"},\"Edges\":{\"StructTag\":\"json:\\\"-\\\"\"},\"EntSQL\":{\"on_delete\":\"RESTRICT\",\"with_comments\":true}}},{\"name\":\"Role\",\"config\":{\"Table\":\"\"},\"edges\":[{\"name\":\"permissions\",\"type\":\"Permission\",\"annotations\":{\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"users\",\"type\":\"User\",\"annotations\":{\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}}],\"fields\":[{\"name\":\"id\",\"type\":{\"Type\":16,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"position\":{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint32\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"name\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"unique\":true,\"validators\":1,\"position\":{\"Index\":1,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"maxLength\":255,\"minLength\":1,\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"description\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"optional\":true,\"position\":{\"Index\":2,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"maxLength\":255,\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"created_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"default\":true,\"default_kind\":19,\"immutable\":true,\"position\":{\"Index\":3,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":true,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"updated_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"update_default\":true,\"immutable\":true,\"position\":{\"Index\":4,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":true,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}}],\"annotations\":{\"Edges\":{\"StructTag\":\"json:\\\"-\\\"\"},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"User\",\"config\":{\"Table\":\"\"},\"edges\":[{\"name\":\"roles\",\"type\":\"Role\",\"ref_name\":\"users\",\"inverse\":true,\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":2},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"access_tokens\",\"type\":\"AccessToken\",\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":1},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"refresh_tokens\",\"type\":\"AccessToken\",\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":1},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}},{\"name\":\"personal_tokens\",\"type\":\"PersonalToken\",\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":1},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}}],\"fields\":[{\"name\":\"deleted_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"position\":{\"Index\":0,\"MixedIn\":true,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":null,\"Skip\":true,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"id\",\"type\":{\"Type\":18,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"position\":{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"uint64\",\"minimum\":1,\"type\":\"integer\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"username\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"unique\":true,\"immutable\":true,\"validators\":1,\"position\":{\"Index\":1,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"maxLength\":255,\"minLength\":2,\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"email\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"unique\":true,\"nillable\":true,\"optional\":true,\"position\":{\"Index\":2,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"format\":\"email\",\"type\":\"string\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"password\",\"type\":{\"Type\":7,\"Ident\":\"\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"validators\":1,\"position\":{\"Index\":3,\"MixedIn\":false,\"MixinIndex\":0},\"sensitive\":true,\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"maxLength\":255,\"minLength\":8,\"type\":\"string\"},\"Skip\":true,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"attr\",\"type\":{\"Type\":3,\"Ident\":\"*map[string]interface {}\",\"PkgPath\":\"\",\"PkgName\":\"\",\"Nillable\":true,\"RType\":{\"Name\":\"\",\"Ident\":\"map[string]interface {}\",\"Kind\":22,\"PkgPath\":\"\",\"Methods\":{}}},\"optional\":true,\"position\":{\"Index\":4,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":false,\"Schema\":{\"properties\":{\"dept\":{\"format\":\"uint32\",\"minimum\":1,\"summary\":\"Department ID\",\"type\":\"integer\"},\"level\":{\"format\":\"uint8\",\"minimum\":1,\"summary\":\"Security Clarence Level\",\"type\":\"integer\"}},\"required\":[\"dept\",\"level\"],\"type\":\"object\"},\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"created_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"default\":true,\"default_kind\":19,\"immutable\":true,\"position\":{\"Index\":5,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":true,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}},{\"name\":\"updated_at\",\"type\":{\"Type\":2,\"Ident\":\"\",\"PkgPath\":\"time\",\"PkgName\":\"\",\"Nillable\":false,\"RType\":null},\"nillable\":true,\"optional\":true,\"update_default\":true,\"immutable\":true,\"position\":{\"Index\":6,\"MixedIn\":false,\"MixinIndex\":0},\"annotations\":{\"EntOAS\":{\"Create\":{\"Groups\":null,\"Policy\":0},\"Delete\":{\"Groups\":null,\"Policy\":0},\"Example\":null,\"Groups\":null,\"List\":{\"Groups\":null,\"Policy\":0},\"Read\":{\"Groups\":null,\"Policy\":0},\"ReadOnly\":true,\"Schema\":null,\"Skip\":false,\"Update\":{\"Groups\":null,\"Policy\":0}}}}],\"hooks\":[{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0}],\"interceptors\":[{\"Index\":0,\"MixedIn\":false,\"MixinIndex\":0}],\"annotations\":{\"Edges\":{\"StructTag\":\"json:\\\"-\\\"\"},\"EntSQL\":{\"on_delete\":\"RESTRICT\"}}}],\"Features\":[\"intercept\",\"schema/snapshot\",\"sql/execquery\",\"sql/versioned-migration\"]}"