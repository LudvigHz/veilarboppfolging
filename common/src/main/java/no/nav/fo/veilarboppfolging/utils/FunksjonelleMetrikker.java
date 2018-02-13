package no.nav.fo.veilarboppfolging.utils;

import no.nav.fo.veilarboppfolging.domain.Tilordning;
import no.nav.metrics.Event;
import no.nav.metrics.MetricsFactory;

import java.util.Date;
import java.util.Optional;

public class FunksjonelleMetrikker {
    public static Tilordning lestAvVeileder(Tilordning tilordning) {
        Event event = MetricsFactory.createEvent("tilordnet.veileder.lest");
        Optional.of(tilordning)
                .map(Tilordning::getSistTilordnet)
                .map(Date::getTime)
                .map(FunksjonelleMetrikker::msSiden)
                .ifPresent(ms -> event.addFieldToReport("ms", ms));
        event.report();
        return tilordning;
    }

    private static long msSiden(long time){
        return new Date().getTime() - time;
    }

    public static void startKvp() {
        MetricsFactory.createEvent("kvp.started").report();
    }

    public static void stopKvp() {
        MetricsFactory.createEvent("kvp.stopped").report();
    }

    private FunksjonelleMetrikker() {
    }
}
