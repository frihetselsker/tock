use crate::ErrorCode;

pub trait Session {
    type IdleToken;
    type ActiveToken;
}

pub trait Context<S: Session> {
    type Saved;

    fn save_context(
        &self,
        active: S::ActiveToken,
    ) -> Result<(S::IdleToken, Self::Saved), (ErrorCode, S::ActiveToken)>;

    fn load_context(
        &self,
        idle: S::IdleToken,
        saved: Self::Saved,
    ) -> Result<S::ActiveToken, (ErrorCode, S::IdleToken, Self::Saved)>;
}
