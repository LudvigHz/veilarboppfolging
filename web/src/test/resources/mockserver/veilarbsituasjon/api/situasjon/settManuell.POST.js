response.setStatus(200);
response.setResponseJson(
    {
        "fnr": "12345678910",
        "reservasjonKRR": false,
        "manuell": true,
        "underOppfolging": true,
        "vilkarMaBesvares": false,
        "oppfolgingUtgang": "2010-12-03T10:15:30Z",
        "kanStarteOppfolging": true,
        "avslutningStatus": {
            "kanAvslutte": false,
            "underOppfolging": false,
            "harYtelser": false,
            "harTiltak": false,
            "inaktiveringsDato": "2017-06-18T10:15:30Z"
        }
    }
);
