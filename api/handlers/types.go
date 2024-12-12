package handlers

func userAttrFromMap(am map[string]interface{}) *struct {
	Dept  uint32 `json:"dept"`
	Level uint8  `json:"level"`
} {
	return &struct {
		Dept  uint32 `json:"dept"`
		Level uint8  `json:"level"`
	}{Dept: uint32(am["dept"].(float64)), Level: uint8(am["level"].(float64))}
}

func userAttrToMap(
	as struct {
		Dept  uint32 `json:"dept"`
		Level uint8  `json:"level"`
	},
) *map[string]interface{} {
	var d interface{} = float64(as.Dept)
	var l interface{} = float64(as.Level)
	return &map[string]interface{}{"dept": d, "level": l}
}

func userAttrMapOf(dept uint32, level uint8) *map[string]interface{} {
	var d interface{} = float64(dept)
	var l interface{} = float64(level)
	return &map[string]interface{}{"dept": d, "level": l}
}

func userAttrOf(dept uint32, level uint8) *struct {
	Dept  uint32 `json:"dept"`
	Level uint8  `json:"level"`
} {
	return &struct {
		Dept  uint32 `json:"dept"`
		Level uint8  `json:"level"`
	}{Dept: dept, Level: level}
}
