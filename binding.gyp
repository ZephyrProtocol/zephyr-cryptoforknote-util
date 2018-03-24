{
    "targets": [
        {
            "target_name": "cryptonote",
            "sources": [
                "src/main.cc",
            ],
            "include_dirs": [
                "src",
                "src/contrib/epee/include",
                "<!(node -e \"require('nan')\")",
            ],
            "link_settings": {
                "libraries": [
                    "-lboost_system",
                    "-lboost_date_time",
                ]
            },
            "cflags_cc!": [ "-fno-exceptions", "-fno-rtti" ],
            "cflags_cc": [
                  "-std=c++0x",
                  "-fexceptions",
                  "-frtti",
            ],
            "xcode_settings": {
              "OTHER_CFLAGS": ["-fexceptions", "-frtti"]
            }
        }
    ]
}
