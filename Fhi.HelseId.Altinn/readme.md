# Information on Fhi.HelseId.Altinn

This is a seperate package for access to HelseId and Altinn. 
It is meant to be used together with Fhi.HelseId, but is technically independent.

Be aware of [this Linq.Async issue](https://github.com/dotnet/efcore/issues/18124) about ambiguities that you might encounter if you also use Entity Framework. 

There exist [an easy workaround](https://github.com/dotnet/efcore/issues/18124#issuecomment-536837372) that can be used. 
